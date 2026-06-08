"""
IAM Findings Aggregator — Lab 5

Collects IAM security data from four sources and writes NDJSON
(one JSON object per line) to S3 under Hive-partitioned prefixes
that AWS Glue can crawl and Athena can query.

Sources:
  1. Security Hub  — active findings on IAM resource types
  2. IAM Access Analyzer — external access findings
  3. IAM API       — access keys > threshold age, unused role permissions
  4. CloudTrail    — AccessDenied events caused by SCPs (last 24 h)

Environment variables:
  FINDINGS_BUCKET         — S3 bucket name (required)
  ANALYZER_ARN            — Access Analyzer ARN (optional; skips if absent)
  KEY_AGE_THRESHOLD_DAYS  — days before a key is considered stale (default 90)
  AWS_DEFAULT_REGION      — set automatically by Lambda runtime
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_BUCKET = os.environ["FINDINGS_BUCKET"]
ANALYZER_ARN = os.environ.get("ANALYZER_ARN", "")
KEY_AGE_THRESHOLD_DAYS = int(os.environ.get("KEY_AGE_THRESHOLD_DAYS", "90"))
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client(service):
    return boto3.client(service, region_name=REGION)


def _write_ndjson(bucket: str, key: str, records: list, collected_at: str) -> None:
    """Write records as NDJSON to S3. Each record gets a _collected_at field."""
    lines = []
    for record in records:
        record["_collected_at"] = collected_at
        lines.append(json.dumps(record, default=str))
    body = "\n".join(lines)
    _client("s3").put_object(
        Bucket=bucket,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="application/x-ndjson",
    )
    logger.info("s3://%s/%s  (%d records)", bucket, key, len(records))


# ---------------------------------------------------------------------------
# Source 1: Security Hub findings on IAM resource types
# ---------------------------------------------------------------------------

_SH_RESOURCE_TYPES = [
    {"Value": "AwsIamRole",        "Comparison": "EQUALS"},
    {"Value": "AwsIamUser",        "Comparison": "EQUALS"},
    {"Value": "AwsIamPolicy",      "Comparison": "EQUALS"},
    {"Value": "AwsIamAccessKey",   "Comparison": "EQUALS"},
    {"Value": "AwsIamGroup",       "Comparison": "EQUALS"},
]


def collect_security_hub_findings() -> list:
    client = _client("securityhub")
    findings = []
    paginator = client.get_paginator("get_findings")
    filters = {
        "ResourceType": _SH_RESOURCE_TYPES,
        "RecordState":     [{"Value": "ACTIVE",    "Comparison": "EQUALS"}],
        "WorkflowStatus":  [{"Value": "NEW",        "Comparison": "EQUALS"},
                            {"Value": "NOTIFIED",   "Comparison": "EQUALS"}],
    }
    for page in paginator.paginate(Filters=filters, MaxResults=100):
        for f in page["Findings"]:
            resource = f.get("Resources", [{}])[0]
            findings.append({
                "finding_id":         f.get("Id"),
                "title":              f.get("Title"),
                "description":        (f.get("Description") or "")[:500],
                "severity":           f.get("Severity", {}).get("Label"),
                "generator_id":       f.get("GeneratorId"),
                "resource_type":      resource.get("Type"),
                "resource_id":        resource.get("Id"),
                "resource_region":    resource.get("Region"),
                "created_at":         f.get("CreatedAt"),
                "updated_at":         f.get("UpdatedAt"),
                "workflow_status":    f.get("Workflow", {}).get("Status"),
                "compliance_status":  f.get("Compliance", {}).get("Status"),
                "product_arn":        f.get("ProductArn"),
            })
    return findings


# ---------------------------------------------------------------------------
# Source 2: IAM Access Analyzer findings
# ---------------------------------------------------------------------------

def collect_access_analyzer_findings() -> list:
    if not ANALYZER_ARN:
        logger.info("ANALYZER_ARN not set — skipping Access Analyzer collection")
        return []

    client = _client("accessanalyzer")
    findings = []
    try:
        paginator = client.get_paginator("list_findings")
        for page in paginator.paginate(
            analyzerArn=ANALYZER_ARN,
            filter={"status": {"eq": ["ACTIVE"]}},
        ):
            for f in page["findings"]:
                findings.append({
                    "finding_id":    f.get("id"),
                    "finding_type":  f.get("findingType"),
                    "resource":      f.get("resource"),
                    "resource_type": f.get("resourceType"),
                    "status":        f.get("status"),
                    "is_public":     f.get("isPublic", False),
                    "created_at":    f.get("createdAt"),
                    "updated_at":    f.get("updatedAt"),
                    "principal":     json.dumps(f.get("principal", {})),
                    "action":        json.dumps(f.get("action", [])),
                    "condition":     json.dumps(f.get("condition", {})),
                })
    except Exception as exc:
        logger.warning("Access Analyzer error: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# Source 3a: Stale access keys (Active and older than threshold)
# ---------------------------------------------------------------------------

def collect_stale_access_keys(now: datetime) -> list:
    iam = _client("iam")
    threshold = now - timedelta(days=KEY_AGE_THRESHOLD_DAYS)
    stale = []

    user_paginator = iam.get_paginator("list_users")
    for upage in user_paginator.paginate():
        for user in upage["Users"]:
            username = user["UserName"]
            key_paginator = iam.get_paginator("list_access_keys")
            for kpage in key_paginator.paginate(UserName=username):
                for key in kpage["AccessKeyMetadata"]:
                    create_date = key["CreateDate"]
                    if key["Status"] != "Active" or create_date >= threshold:
                        continue
                    age_days = (now - create_date).days
                    last_used_resp = iam.get_access_key_last_used(
                        AccessKeyId=key["AccessKeyId"]
                    )
                    last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
                    last_used_date = last_used_info.get("LastUsedDate")
                    stale.append({
                        "username":          username,
                        "access_key_id":     key["AccessKeyId"],
                        "status":            key["Status"],
                        "create_date":       create_date.isoformat(),
                        "age_days":          age_days,
                        "last_used_date":    last_used_date.isoformat() if last_used_date else None,
                        "last_used_service": last_used_info.get("ServiceName"),
                        "last_used_region":  last_used_info.get("Region"),
                    })
    return stale


# ---------------------------------------------------------------------------
# Source 3b: Unused role permissions
# ---------------------------------------------------------------------------

_SERVICE_ROLE_PATHS = ("/aws-service-role/", "/service-role/")


def collect_unused_role_permissions() -> list:
    iam = _client("iam")
    results = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_arn = role["Arn"]
            if any(p in role_arn for p in _SERVICE_ROLE_PATHS):
                continue  # AWS-managed service roles carry many permissions by design

            try:
                job_id = iam.generate_service_last_accessed_details(Arn=role_arn)["JobId"]
                for _ in range(15):
                    details = iam.get_service_last_accessed_details(JobId=job_id)
                    if details["JobStatus"] == "COMPLETED":
                        break
                    if details["JobStatus"] == "FAILED":
                        raise RuntimeError(f"Job {job_id} failed")
                    time.sleep(1)
                else:
                    logger.warning("Timeout waiting for service access details: %s", role["RoleName"])
                    continue

                services = details.get("ServicesLastAccessed", [])
                total = len(services)
                unused = [s for s in services if s.get("LastAuthenticated") is None]

                if total == 0:
                    continue

                results.append({
                    "role_name":               role["RoleName"],
                    "role_arn":                role_arn,
                    "path":                    role.get("Path"),
                    "create_date":             role["CreateDate"].isoformat(),
                    "total_services_with_access": total,
                    "unused_services_count":   len(unused),
                    "used_services_count":     total - len(unused),
                    "unused_services_percent": round(len(unused) / total * 100, 1),
                    "unused_services": [s["ServiceName"] for s in unused][:20],
                })
            except Exception as exc:
                logger.warning("Could not analyse role %s: %s", role["RoleName"], exc)

    return results


# ---------------------------------------------------------------------------
# Source 4: SCP violation events from CloudTrail (last 24 h)
# ---------------------------------------------------------------------------

_SCP_MARKERS = ("Service Control Policy", "explicit deny in a service control policy")


def collect_scp_violations(now: datetime) -> list:
    ct = _client("cloudtrail")
    violations = []
    start_time = now - timedelta(hours=24)

    try:
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "ErrorCode", "AttributeValue": "AccessDenied"}],
            StartTime=start_time,
            EndTime=now,
        ):
            for event in page["Events"]:
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                except json.JSONDecodeError:
                    continue

                error_msg = detail.get("errorMessage", "")
                if not any(marker.lower() in error_msg.lower() for marker in _SCP_MARKERS):
                    continue

                violations.append({
                    "event_id":      event.get("EventId"),
                    "event_name":    event.get("EventName"),
                    "event_time":    event["EventTime"].isoformat(),
                    "username":      event.get("Username"),
                    "error_code":    detail.get("errorCode"),
                    "error_message": error_msg[:500],
                    "source_ip":     detail.get("sourceIPAddress"),
                    "user_agent":    (detail.get("userAgent") or "")[:200],
                    "aws_region":    detail.get("awsRegion"),
                    "event_source":  detail.get("eventSource"),
                    "user_identity": json.dumps(detail.get("userIdentity", {}))[:500],
                    "request_params": json.dumps(detail.get("requestParameters") or {})[:500],
                })
    except Exception as exc:
        logger.warning("CloudTrail lookup error: %s", exc)

    return violations


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    now = datetime.now(timezone.utc)
    partition = f"year={now.year}/month={now.month:02d}/day={now.day:02d}"
    collected_at = now.isoformat()

    categories = {
        "security_hub_findings":   collect_security_hub_findings,
        "access_analyzer_findings": collect_access_analyzer_findings,
        "stale_access_keys":        lambda: collect_stale_access_keys(now),
        "unused_role_permissions":  collect_unused_role_permissions,
        "scp_violations":           lambda: collect_scp_violations(now),
    }

    summary = {}
    for category, fn in categories.items():
        try:
            records = fn()
            s3_key = f"findings/{category}/{partition}/data.json"
            _write_ndjson(FINDINGS_BUCKET, s3_key, records, collected_at)
            summary[category] = len(records)
        except Exception as exc:
            logger.error("Error collecting %s: %s", category, exc, exc_info=True)
            summary[f"{category}_error"] = str(exc)

    logger.info("Aggregation complete: %s", summary)
    return {"statusCode": 200, "body": summary}
