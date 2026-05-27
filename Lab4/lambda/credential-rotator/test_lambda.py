import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("ROTATION_AGE_DAYS", "90")
os.environ.setdefault("SNS_TOPIC_ARN", "")
os.environ.setdefault("SECRET_PREFIX", "iam/access-keys")
os.environ.setdefault("PROTECTED_USERS", '["system-user"]')
os.environ.setdefault("DRY_RUN", "false")

import lambda_function  # noqa: E402

_AWS_PARTITION = os.environ.get("AWS_PARTITION", "aws")
_AWS_REGION = os.environ.get("PRIMARY_REGION", os.environ.get("AWS_DEFAULT_REGION", ""))
_AWS_ACCOUNT_ID = os.environ.get("SECURITY_ACCOUNT_ID", os.environ.get("AWS_ACCOUNT_ID", ""))
_SNS_TOPIC_NAME = os.environ.get("SNS_TOPIC_NAME", "")
_TEST_SECRET_PREFIX = os.environ.get("SECRET_PREFIX", "iam/access-keys")

# `or` ensures an empty SNS_TOPIC_ARN env var falls through to the constructed value
_TEST_SNS_ARN = os.environ.get("SNS_TOPIC_ARN") or f"arn:{_AWS_PARTITION}:sns:{_AWS_REGION}:{_AWS_ACCOUNT_ID}:{_SNS_TOPIC_NAME}"


def _make_key(key_id, username, age_days, status="Active"):
    return {
        "AccessKeyId": key_id,
        "UserName": username,
        "Status": status,
        "CreateDate": datetime.now(timezone.utc) - timedelta(days=age_days),
    }


class TestListAllUsers(unittest.TestCase):
    def test_returns_users_from_paginator(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
        ]
        users = lambda_function._list_all_users(iam)
        self.assertEqual([u["UserName"] for u in users], ["alice", "bob"])


class TestProcessUser(unittest.TestCase):
    def _empty_results(self):
        return {"rotated": [], "skipped": [], "errors": [], "notified": []}

    def test_protected_user_is_skipped(self):
        iam = MagicMock()
        results = self._empty_results()
        lambda_function._process_user(iam, "system-user", results)
        iam.list_access_keys.assert_not_called()
        self.assertEqual(results["skipped"][0]["reason"], "protected")

    def test_fresh_key_is_not_rotated(self):
        iam = MagicMock()
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [_make_key("AKIA1", "alice", age_days=10)]
        }
        results = self._empty_results()
        lambda_function._process_user(iam, "alice", results)
        self.assertIn("no stale", results["skipped"][0]["reason"])

    def test_inactive_stale_key_is_not_rotated(self):
        iam = MagicMock()
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [_make_key("AKIA_OLD", "alice", age_days=100, status="Inactive")]
        }
        results = self._empty_results()
        lambda_function._process_user(iam, "alice", results)
        self.assertIn("no stale", results["skipped"][0]["reason"])

    @patch("lambda_function._store_secret")
    @patch("lambda_function._send_pre_rotation_notice")
    def test_stale_active_key_is_rotated(self, mock_notify, mock_store):
        iam = MagicMock()
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [_make_key("AKIA_OLD", "bob", age_days=100)]
        }
        iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIA_NEW", "SecretAccessKey": "secret", "UserName": "bob"}
        }
        results = self._empty_results()
        lambda_function._process_user(iam, "bob", results)

        iam.create_access_key.assert_called_once_with(UserName="bob")
        iam.delete_access_key.assert_called_once_with(UserName="bob", AccessKeyId="AKIA_OLD")
        self.assertEqual(results["rotated"][0]["old_key"], "AKIA_OLD")
        self.assertEqual(results["rotated"][0]["new_key"], "AKIA_NEW")

    @patch.object(lambda_function, "DRY_RUN", True)
    @patch("lambda_function._store_secret")
    @patch("lambda_function._send_pre_rotation_notice")
    def test_dry_run_skips_rotation(self, mock_notify, mock_store):
        iam = MagicMock()
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [_make_key("AKIA_OLD", "carol", age_days=100)]
        }
        results = self._empty_results()
        lambda_function._process_user(iam, "carol", results)
        iam.create_access_key.assert_not_called()
        self.assertEqual(results["skipped"][0]["reason"], "dry_run")


class TestFreeKeySlot(unittest.TestCase):
    def test_deletes_inactive_key_when_available(self):
        iam = MagicMock()
        all_keys = [
            _make_key("AKIA_OLD", "dave", 100, "Active"),
            _make_key("AKIA_INACT", "dave", 200, "Inactive"),
        ]
        lambda_function._free_key_slot(iam, "dave", "AKIA_OLD", all_keys)
        iam.delete_access_key.assert_called_once_with(UserName="dave", AccessKeyId="AKIA_INACT")
        iam.update_access_key.assert_not_called()

    def test_deactivates_stale_key_when_no_inactive_available(self):
        iam = MagicMock()
        all_keys = [
            _make_key("AKIA_OLD", "eve", 100, "Active"),
            _make_key("AKIA_OTHER", "eve", 50, "Active"),
        ]
        lambda_function._free_key_slot(iam, "eve", "AKIA_OLD", all_keys)
        iam.update_access_key.assert_called_once_with(
            UserName="eve", AccessKeyId="AKIA_OLD", Status="Inactive"
        )

    def test_does_not_delete_the_key_being_rotated(self):
        iam = MagicMock()
        all_keys = [
            _make_key("AKIA_OLD", "frank", 100, "Active"),
            _make_key("AKIA_OLD", "frank", 100, "Inactive"),
        ]
        lambda_function._free_key_slot(iam, "frank", "AKIA_OLD", all_keys)
        iam.update_access_key.assert_called_once()


class TestSendPreRotationNotice(unittest.TestCase):
    @patch.object(lambda_function, "SNS_TOPIC_ARN", _TEST_SNS_ARN)
    @patch("boto3.client")
    def test_publishes_to_sns(self, mock_boto):
        mock_sns = MagicMock()
        mock_boto.return_value = mock_sns
        results = {"notified": []}
        lambda_function._send_pre_rotation_notice("grace", "AKIA_X", 95, results)
        mock_sns.publish.assert_called_once()
        self.assertEqual(results["notified"][0]["user"], "grace")
        self.assertEqual(results["notified"][0]["phase"], "pre")

    @patch.object(lambda_function, "SNS_TOPIC_ARN", "")
    @patch("boto3.client")
    def test_skips_when_no_topic_configured(self, mock_boto):
        results = {"notified": []}
        lambda_function._send_pre_rotation_notice("henry", "AKIA_Y", 100, results)
        mock_boto.assert_not_called()
        self.assertEqual(results["notified"], [])

    @patch.object(lambda_function, "SNS_TOPIC_ARN", _TEST_SNS_ARN)
    @patch("boto3.client")
    def test_warning_logged_on_sns_failure(self, mock_boto):
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("network error")
        mock_boto.return_value = mock_sns
        results = {"notified": []}
        lambda_function._send_pre_rotation_notice("iris", "AKIA_Z", 91, results)
        self.assertEqual(results["notified"], [])


class TestSendPostRotationNotice(unittest.TestCase):
    @patch.object(lambda_function, "SNS_TOPIC_ARN", _TEST_SNS_ARN)
    @patch("boto3.client")
    def test_publishes_completion_notice(self, mock_boto):
        mock_sns = MagicMock()
        mock_boto.return_value = mock_sns
        results = {"notified": []}
        lambda_function._send_post_rotation_notice("grace", "AKIA_OLD", "AKIA_NEW", results)
        mock_sns.publish.assert_called_once()
        call_kwargs = mock_sns.publish.call_args[1]
        self.assertIn("AKIA_NEW", call_kwargs["Message"])
        self.assertIn("AKIA_OLD", call_kwargs["Message"])
        self.assertNotIn("SecretAccessKey", call_kwargs["Message"])
        self.assertEqual(results["notified"][0]["phase"], "post")

    @patch.object(lambda_function, "SNS_TOPIC_ARN", "")
    @patch("boto3.client")
    def test_skips_when_no_topic_configured(self, mock_boto):
        results = {"notified": []}
        lambda_function._send_post_rotation_notice("henry", "AKIA_OLD", "AKIA_NEW", results)
        mock_boto.assert_not_called()
        self.assertEqual(results["notified"], [])

    @patch.object(lambda_function, "SNS_TOPIC_ARN", _TEST_SNS_ARN)
    @patch("boto3.client")
    def test_message_contains_secrets_manager_path(self, mock_boto):
        mock_sns = MagicMock()
        mock_boto.return_value = mock_sns
        results = {"notified": []}
        lambda_function._send_post_rotation_notice("alice", "AKIA_OLD", "AKIA_NEW", results)
        call_kwargs = mock_sns.publish.call_args[1]
        self.assertIn(f"{_TEST_SECRET_PREFIX}/alice", call_kwargs["Message"])

    @patch.object(lambda_function, "SNS_TOPIC_ARN", _TEST_SNS_ARN)
    @patch("boto3.client")
    def test_warning_logged_on_sns_failure(self, mock_boto):
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("network error")
        mock_boto.return_value = mock_sns
        results = {"notified": []}
        lambda_function._send_post_rotation_notice("bob", "AKIA_OLD", "AKIA_NEW", results)
        self.assertEqual(results["notified"], [])


class TestStoreSecret(unittest.TestCase):
    @patch("boto3.client")
    def test_updates_existing_secret(self, mock_boto):
        mock_sm = MagicMock()
        mock_boto.return_value = mock_sm
        new_key = {"AccessKeyId": "AKIA_NEW", "SecretAccessKey": "s3cr3t", "UserName": "jack"}
        lambda_function._store_secret("jack", new_key)
        mock_sm.put_secret_value.assert_called_once()
        mock_sm.create_secret.assert_not_called()

    @patch("boto3.client")
    def test_creates_secret_when_not_found(self, mock_boto):
        mock_sm = MagicMock()
        mock_boto.return_value = mock_sm
        mock_sm.exceptions.ResourceNotFoundException = Exception
        mock_sm.put_secret_value.side_effect = Exception("ResourceNotFoundException")
        new_key = {"AccessKeyId": "AKIA_NEW", "SecretAccessKey": "s3cr3t", "UserName": "kate"}
        lambda_function._store_secret("kate", new_key)
        mock_sm.create_secret.assert_called_once()

    @patch("boto3.client")
    def test_secret_path_uses_prefix_from_env(self, mock_boto):
        mock_sm = MagicMock()
        mock_boto.return_value = mock_sm
        new_key = {"AccessKeyId": "AKIA_NEW", "SecretAccessKey": "s3cr3t", "UserName": "leo"}
        lambda_function._store_secret("leo", new_key)
        call_kwargs = mock_sm.put_secret_value.call_args[1]
        self.assertTrue(call_kwargs["SecretId"].startswith(_TEST_SECRET_PREFIX))


class TestLambdaHandler(unittest.TestCase):
    @patch("lambda_function._process_user", side_effect=Exception("boom"))
    @patch("lambda_function._list_all_users", return_value=[{"UserName": "liam"}])
    def test_per_user_errors_are_captured(self, _mock_list, _mock_process):
        result = lambda_function.lambda_handler({}, {})
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["user"], "liam")
        self.assertEqual(result["errors"][0]["error"], "boom")

    @patch("lambda_function._list_all_users", return_value=[])
    def test_empty_account_returns_empty_results(self, _mock_list):
        result = lambda_function.lambda_handler({}, {})
        self.assertEqual(result, {"rotated": [], "skipped": [], "errors": [], "notified": []})


if __name__ == "__main__":
    unittest.main()
