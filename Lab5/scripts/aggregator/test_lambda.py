"""
Unit tests for the IAM Findings Aggregator Lambda (Lab 5).

All AWS API calls are mocked so no real credentials are required.
Run with:  python -m pytest test_lambda.py -v
"""

import importlib
import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Set required environment variables BEFORE importing the module under test
# ---------------------------------------------------------------------------
import os

os.environ.setdefault("FINDINGS_BUCKET", "test-bucket")
os.environ.setdefault("ANALYZER_ARN", "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test")
os.environ.setdefault("KEY_AGE_THRESHOLD_DAYS", "90")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import lambda_function as lf  # noqa: E402  (import after env vars)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 6, 8, 1, 0, 0, tzinfo=timezone.utc)


def _make_key_metadata(key_id, status, create_date):
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": create_date}


# ---------------------------------------------------------------------------
# _write_ndjson
# ---------------------------------------------------------------------------

class TestWriteNdjson:
    def test_writes_one_line_per_record(self):
        mock_s3 = MagicMock()
        records = [{"a": 1}, {"b": 2}]
        with patch.object(lf, "_client", return_value=mock_s3):
            lf._write_ndjson("bucket", "key/data.json", records, "2026-06-08T01:00:00+00:00")

        call_kwargs = mock_s3.put_object.call_args.kwargs
        body_lines = call_kwargs["Body"].decode("utf-8").strip().split("\n")
        assert len(body_lines) == 2
        assert json.loads(body_lines[0])["a"] == 1
        assert json.loads(body_lines[1])["b"] == 2

    def test_adds_collected_at_to_each_record(self):
        mock_s3 = MagicMock()
        records = [{"x": 42}]
        with patch.object(lf, "_client", return_value=mock_s3):
            lf._write_ndjson("bucket", "key", records, "ts123")

        body = mock_s3.put_object.call_args.kwargs["Body"].decode("utf-8")
        assert json.loads(body)["_collected_at"] == "ts123"

    def test_empty_records_writes_empty_body(self):
        mock_s3 = MagicMock()
        with patch.object(lf, "_client", return_value=mock_s3):
            lf._write_ndjson("bucket", "key", [], "ts")

        body = mock_s3.put_object.call_args.kwargs["Body"].decode("utf-8")
        assert body == ""


# ---------------------------------------------------------------------------
# collect_stale_access_keys
# ---------------------------------------------------------------------------

class TestCollectStaleAccessKeys:
    def _make_mock_iam(self, users, key_metadata, last_used_date=None):
        mock_iam = MagicMock()
        mock_iam.get_paginator.side_effect = lambda op: {
            "list_users":       _paginator([{"Users": users}]),
            "list_access_keys": _paginator([{"AccessKeyMetadata": key_metadata}]),
        }[op]
        mock_iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "LastUsedDate": last_used_date,
                "ServiceName": "s3",
                "Region": "us-east-1",
            }
        }
        return mock_iam

    def test_returns_stale_active_keys(self):
        from datetime import timedelta
        old_date = NOW - timedelta(days=100)
        users = [{"UserName": "alice"}]
        keys = [_make_key_metadata("AKIA1", "Active", old_date)]
        mock_iam = self._make_mock_iam(users, keys)

        with patch.object(lf, "_client", return_value=mock_iam):
            result = lf.collect_stale_access_keys(NOW)

        assert len(result) == 1
        assert result[0]["username"] == "alice"
        assert result[0]["age_days"] == 100

    def test_skips_inactive_keys(self):
        from datetime import timedelta
        old_date = NOW - timedelta(days=100)
        users = [{"UserName": "bob"}]
        keys = [_make_key_metadata("AKIA2", "Inactive", old_date)]
        mock_iam = self._make_mock_iam(users, keys)

        with patch.object(lf, "_client", return_value=mock_iam):
            result = lf.collect_stale_access_keys(NOW)

        assert result == []

    def test_skips_young_keys(self):
        from datetime import timedelta
        recent = NOW - timedelta(days=30)
        users = [{"UserName": "carol"}]
        keys = [_make_key_metadata("AKIA3", "Active", recent)]
        mock_iam = self._make_mock_iam(users, keys)

        with patch.object(lf, "_client", return_value=mock_iam):
            result = lf.collect_stale_access_keys(NOW)

        assert result == []


# ---------------------------------------------------------------------------
# collect_access_analyzer_findings
# ---------------------------------------------------------------------------

class TestCollectAccessAnalyzerFindings:
    def test_skips_when_no_analyzer_arn(self):
        original = lf.ANALYZER_ARN
        lf.ANALYZER_ARN = ""
        try:
            result = lf.collect_access_analyzer_findings()
        finally:
            lf.ANALYZER_ARN = original
        assert result == []

    def test_returns_active_findings(self):
        finding = {
            "id": "finding-1",
            "findingType": "ExternalAccess",
            "resource": "arn:aws:s3:::my-bucket",
            "resourceType": "AWS::S3::Bucket",
            "status": "ACTIVE",
            "isPublic": True,
            "createdAt": NOW,
            "updatedAt": NOW,
            "principal": {"AWS": "*"},
            "action": ["s3:GetObject"],
            "condition": {},
        }
        mock_aa = MagicMock()
        mock_aa.get_paginator.return_value = _paginator([{"findings": [finding]}])

        with patch.object(lf, "_client", return_value=mock_aa):
            result = lf.collect_access_analyzer_findings()

        assert len(result) == 1
        assert result[0]["finding_id"] == "finding-1"
        assert result[0]["is_public"] is True


# ---------------------------------------------------------------------------
# collect_scp_violations
# ---------------------------------------------------------------------------

class TestCollectSCPViolations:
    def _make_event(self, error_msg):
        return {
            "EventId": "evt-1",
            "EventName": "CreateRole",
            "EventTime": NOW,
            "Username": "dave",
            "CloudTrailEvent": json.dumps({
                "errorCode": "AccessDenied",
                "errorMessage": error_msg,
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "aws-cli/2",
                "awsRegion": "us-east-1",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {"type": "IAMUser"},
                "requestParameters": None,
            }),
        }

    def test_captures_scp_violations(self):
        event = self._make_event("explicit deny in a service control policy")
        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _paginator([{"Events": [event]}])

        with patch.object(lf, "_client", return_value=mock_ct):
            result = lf.collect_scp_violations(NOW)

        assert len(result) == 1
        assert result[0]["username"] == "dave"

    def test_ignores_non_scp_denials(self):
        event = self._make_event("User is not authorized to perform this action")
        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _paginator([{"Events": [event]}])

        with patch.object(lf, "_client", return_value=mock_ct):
            result = lf.collect_scp_violations(NOW)

        assert result == []

    def test_handles_cloudtrail_error_gracefully(self):
        mock_ct = MagicMock()
        mock_ct.get_paginator.side_effect = Exception("ThrottlingException")

        with patch.object(lf, "_client", return_value=mock_ct):
            result = lf.collect_scp_violations(NOW)

        assert result == []


# ---------------------------------------------------------------------------
# lambda_handler integration smoke test
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_200_on_success(self):
        mock_s3 = MagicMock()
        mock_sh = MagicMock()
        mock_sh.get_paginator.return_value = _paginator([{"Findings": []}])
        mock_aa = MagicMock()
        mock_aa.get_paginator.return_value = _paginator([{"findings": []}])
        mock_iam = MagicMock()
        mock_iam.get_paginator.return_value = _paginator([{"Users": [], "Roles": []}])
        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _paginator([{"Events": []}])

        def client_factory(service, **_):
            return {
                "s3": mock_s3,
                "securityhub": mock_sh,
                "accessanalyzer": mock_aa,
                "iam": mock_iam,
                "cloudtrail": mock_ct,
            }[service]

        with patch.object(lf, "_client", side_effect=client_factory):
            response = lf.lambda_handler({}, None)

        assert response["statusCode"] == 200
        assert isinstance(response["body"], dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginator(pages):
    """Return a mock paginator whose paginate() yields the given pages."""
    mock_p = MagicMock()
    mock_p.paginate.return_value = iter(pages)
    return mock_p
