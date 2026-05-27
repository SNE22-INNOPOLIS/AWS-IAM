import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ROTATION_AGE_DAYS = int(os.environ.get("ROTATION_AGE_DAYS", "90"))
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SECRET_PREFIX = os.environ.get("SECRET_PREFIX", "iam/access-keys")
PROTECTED_USERS = json.loads(os.environ.get("PROTECTED_USERS", "[]"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"


def lambda_handler(event, context):
    logger.info("Starting IAM access key rotation scan")

    results = {"rotated": [], "skipped": [], "errors": [], "notified": []}
    iam = boto3.client("iam")

    users = _list_all_users(iam)
    logger.info("Found %d IAM users to evaluate", len(users))

    for user in users:
        username = user["UserName"]
        try:
            _process_user(iam, username, results)
        except Exception as exc:
            logger.error("Error processing user %s: %s", username, exc)
            results["errors"].append({"user": username, "error": str(exc)})

    logger.info("Rotation scan complete: %s", json.dumps(results, default=str))
    return results


def _list_all_users(iam):
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def _process_user(iam, username, results):
    if username in PROTECTED_USERS:
        logger.info("Skipping protected user: %s", username)
        results["skipped"].append({"user": username, "reason": "protected"})
        return

    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    now = datetime.now(timezone.utc)

    stale_keys = [
        k
        for k in keys
        if (now - k["CreateDate"]).days >= ROTATION_AGE_DAYS and k["Status"] == "Active"
    ]

    if not stale_keys:
        results["skipped"].append({"user": username, "reason": "no stale active keys"})
        return

    for key in stale_keys:
        key_id = key["AccessKeyId"]
        age_days = (now - key["CreateDate"]).days

        _send_pre_rotation_notice(username, key_id, age_days, results)

        if DRY_RUN:
            logger.info("DRY RUN: would rotate key %s for %s", key_id, username)
            results["skipped"].append({"user": username, "key": key_id, "reason": "dry_run"})
            continue

        _rotate_key(iam, username, key_id, keys, results)


def _send_pre_rotation_notice(username, key_id, age_days, results):
    if not SNS_TOPIC_ARN:
        return

    sns = boto3.client("sns")
    message = (
        f"IAM Access Key Rotation Notice\n\n"
        f"User:    {username}\n"
        f"Key ID:  {key_id}\n"
        f"Key Age: {age_days} days\n\n"
        f"This key exceeds the {ROTATION_AGE_DAYS}-day rotation policy and will be rotated now.\n"
        f"The new credentials will be stored in AWS Secrets Manager at:\n"
        f"  {SECRET_PREFIX}/{username}\n\n"
        f"If this key is used by a critical service, update your application configuration "
        f"immediately after rotation completes."
    )

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[IAM Key Rotation] Action required for {username}",
            Message=message,
        )
        results["notified"].append({"user": username, "key": key_id})
        logger.info("Pre-rotation notice sent for %s / %s", username, key_id)
    except Exception as exc:
        logger.warning("Could not send SNS notice for %s: %s", username, exc)


def _rotate_key(iam, username, old_key_id, all_keys, results):
    # IAM allows a maximum of 2 access keys per user. Free up a slot before creating.
    if len(all_keys) >= 2:
        _free_key_slot(iam, username, old_key_id, all_keys)

    new_key = iam.create_access_key(UserName=username)["AccessKey"]
    logger.info("Created new key %s for %s", new_key["AccessKeyId"], username)

    _store_secret(username, new_key)

    iam.delete_access_key(UserName=username, AccessKeyId=old_key_id)
    logger.info("Deleted old key %s for %s", old_key_id, username)

    results["rotated"].append(
        {
            "user": username,
            "old_key": old_key_id,
            "new_key": new_key["AccessKeyId"],
        }
    )


def _free_key_slot(iam, username, key_being_rotated, all_keys):
    # Prefer deleting an already-inactive key that is NOT the one being rotated.
    inactive = [
        k
        for k in all_keys
        if k["Status"] == "Inactive" and k["AccessKeyId"] != key_being_rotated
    ]
    if inactive:
        victim = min(inactive, key=lambda k: k["CreateDate"])
        logger.info(
            "Deleting inactive key %s for %s to free slot",
            victim["AccessKeyId"],
            username,
        )
        iam.delete_access_key(UserName=username, AccessKeyId=victim["AccessKeyId"])
        return

    # No disposable inactive key — deactivate the stale key so we can create its
    # replacement. The caller deletes the old key after storing the new secret.
    logger.info(
        "No inactive key available; deactivating %s for %s to free slot",
        key_being_rotated,
        username,
    )
    iam.update_access_key(
        UserName=username, AccessKeyId=key_being_rotated, Status="Inactive"
    )


def _store_secret(username, new_key):
    sm = boto3.client("secretsmanager")
    secret_id = f"{SECRET_PREFIX}/{username}"
    payload = json.dumps(
        {
            "AccessKeyId": new_key["AccessKeyId"],
            "SecretAccessKey": new_key["SecretAccessKey"],
            "UserName": username,
            "RotatedAt": datetime.now(timezone.utc).isoformat(),
        }
    )

    try:
        sm.put_secret_value(SecretId=secret_id, SecretString=payload)
        logger.info("Updated secret %s", secret_id)
    except sm.exceptions.ResourceNotFoundException:
        sm.create_secret(
            Name=secret_id,
            Description=f"Rotated IAM access key for {username} — managed by credential-rotator",
            SecretString=payload,
        )
        logger.info("Created new secret %s", secret_id)
