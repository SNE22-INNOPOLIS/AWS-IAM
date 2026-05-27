# Lab 4 — Automated IAM Access Key Rotation

This lab reduces the blast radius of leaked credentials by enforcing **automatic rotation** for all IAM user access keys. A scheduled Lambda function identifies keys older than 90 days, notifies the owner via SNS before acting, creates a replacement key, stores it in AWS Secrets Manager, and deletes the stale key — all without manual intervention.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How the Rotator Works](#how-the-rotator-works)
3. [Key Limit Handling](#key-limit-handling)
4. [Module Structure](#module-structure)
5. [Prerequisites](#prerequisites)
6. [Configuration](#configuration)
7. [Deployment](#deployment)
8. [Testing](#testing)
9. [Monitoring and Alerts](#monitoring-and-alerts)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      Security Account                         │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │               EventBridge (weekly schedule)          │    │
│  │               rate(7 days)                           │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                          │ invoke                             │
│  ┌───────────────────────▼──────────────────────────────┐   │
│  │       Lambda: iam-key-rotator-credential-rotator      │   │
│  │                                                       │   │
│  │  1. List all IAM users                                │   │
│  │  2. Find Active keys older than 90 days               │   │
│  │  3. Send SNS pre-rotation notice                      │   │
│  │  4. Handle 2-key slot limit                           │   │
│  │  5. Create new access key                             │   │
│  │  6. Store new key in Secrets Manager                  │   │
│  │  7. Delete old key                                    │   │
│  └───┬───────────────────┬───────────────────────┬──────┘   │
│      │                   │                        │           │
│      ▼                   ▼                        ▼           │
│  ┌───────┐   ┌────────────────────┐   ┌──────────────────┐  │
│  │  IAM  │   │  Secrets Manager   │   │    SNS Topic     │  │
│  │  API  │   │  iam/access-keys/  │   │  (email alert)   │  │
│  └───────┘   │  <username>        │   └──────────────────┘  │
│              └────────────────────┘          │               │
└──────────────────────────────────────────────│───────────────┘
                                               ▼
                                     Security Team Email
```

---

## How the Rotator Works

### 1. EventBridge Trigger

An EventBridge rule fires on the configured schedule (default `rate(7 days)`). It invokes the Lambda function and passes the event through with no payload — the Lambda manages all state via IAM and Secrets Manager.

### 2. Key Age Evaluation

For every IAM user in the account the function calls `iam:ListAccessKeys`. Any key that is:
- **Status: Active**, and
- **Age ≥ `ROTATION_AGE_DAYS`** (default 90 days)

is flagged for rotation. Inactive keys and fresh keys are skipped. Users listed in `PROTECTED_USERS` are skipped entirely — this is the mechanism for excluding keys used by critical system services.

### 3. Pre-Rotation SNS Notice

Before any key is created or deleted, an SNS email is published to the configured topic with:
- The username and key ID being rotated
- The key age in days
- The Secrets Manager path where the new credentials will be stored
- A reminder to update any application configuration immediately after rotation

This fulfils the "warn before rotating" requirement for critical service keys.

### 4. Key Rotation

```
create new key → store in Secrets Manager → delete old key
```

The new key is written as a JSON secret at `iam/access-keys/<username>`:

```json
{
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "UserName": "alice",
  "RotatedAt": "2026-05-27T00:00:00+00:00"
}
```

If the secret does not yet exist it is created automatically. Subsequent rotations call `PutSecretValue` to update it in place.

---

## Key Limit Handling

IAM enforces a maximum of **2 access keys per user**. When a user already has 2 keys, the Lambda resolves the slot before creating the replacement:

| Existing keys | Resolution |
|---|---|
| 1 Active (stale) + 1 Inactive | Delete the inactive key first, then create new key, then delete stale key |
| 2 Active (both stale) | Deactivate the stale key first, create new key, then delete the now-inactive old key |
| 1 Active (stale) only | Create new key directly, then delete stale key |

In all cases the old stale key is **deleted** (not merely deactivated) once the new key is safely in Secrets Manager. An inactive key is preferred for deletion to avoid disrupting an active non-stale key.

---

## Module Structure

```
Lab4/
├── lambda/
│   └── credential-rotator/
│       ├── lambda_function.py          # Main Lambda handler
│       ├── requirements.txt            # Python dependencies
│       └── test_lambda.py              # Unit tests (15 test cases)
└── terraform/
    ├── main.tf                         # Root — wires modules together
    ├── variables.tf
    ├── outputs.tf
    ├── providers.tf
    ├── backend.tf
    ├── terraform.tfvars
    └── modules/
        ├── notifications/              # SNS topic + email subscription
        │   ├── main.tf
        │   ├── variables.tf
        │   └── outputs.tf
        └── key-rotator/               # Lambda, IAM role, EventBridge rule
            ├── main.tf
            ├── variables.tf
            ├── outputs.tf
            └── files/                 # Generated Lambda zip (git-ignored)
```

---

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with the `security` named profile
- S3 bucket and DynamoDB table for Terraform remote state (created in Lab 1)
- An email address subscribed to the SNS topic (confirmation email sent on first `apply`)

Verify the profile is working:

```bash
aws sts get-caller-identity --profile security
```

---

## Configuration

All environment-specific values are set in `terraform/terraform.tfvars`:

| Variable | Description | Default |
|---|---|---|
| `security_account_id` | Security account AWS ID | — |
| `security_account_profile` | AWS CLI named profile | `security` |
| `primary_region` | AWS region for all resources | `us-east-1` |
| `project_name` | Prefix for all resource names | `iam-key-rotator` |
| `notification_email` | Email address for rotation alerts | — |
| `rotation_age_days` | Keys older than this (days) are rotated | `90` |
| `lambda_schedule_expression` | EventBridge schedule | `rate(7 days)` |
| `enable_dry_run` | Report stale keys without rotating them | `false` |
| `protected_users` | IAM usernames excluded from rotation | `[]` |
| `secret_prefix` | Secrets Manager path prefix | `iam/access-keys` |

### Protecting critical service accounts

Add any IAM username whose key must not be automatically rotated to the `protected_users` list:

```hcl
protected_users = ["ci-deploy-prod", "legacy-app-svc"]
```

The Lambda will log that these users were skipped and the pre-rotation notice will not be sent for them.

---

## Deployment

```bash
cd Lab4/terraform

# 1. Initialise providers and remote state
terraform init

# 2. Validate configuration
terraform validate

# 3. Preview changes
terraform plan -out=tfplan

# 4. Apply
terraform apply tfplan
```

On completion, Terraform prints the key outputs:

```
lambda_function_name  = "iam-key-rotator-credential-rotator-security-lab"
lambda_function_arn   = "arn:aws:lambda:us-east-1:111111111111:function:iam-key-rotator-credential-rotator-security-lab"
lambda_iam_role_arn   = "arn:aws:iam::111111111111:role/iam-key-rotator-credential-rotator-security-lab-role"
sns_topic_arn         = "arn:aws:sns:us-east-1:111111111111:iam-key-rotator-key-rotation-security-lab"
eventbridge_rule_arn  = "arn:aws:events:us-east-1:111111111111:rule/iam-key-rotator-credential-rotator-security-lab-schedule"
cloudwatch_log_group  = "/aws/lambda/iam-key-rotator-credential-rotator-security-lab"
```

After `apply`, **confirm the SNS subscription email** before the first rotation fires — AWS will not deliver notifications to an unconfirmed endpoint.

---

## Testing

### Test 1 — Run unit tests locally

```bash
cd Lab4/lambda/credential-rotator
pip install -r requirements.txt
python -m pytest test_lambda.py -v
```

Expected: all 15 tests pass.

---

### Test 2 — Dry run (no keys modified)

Invoke the Lambda with dry-run mode enabled to verify it identifies stale keys without touching them:

```bash
# Enable dry run temporarily via AWS CLI
aws lambda update-function-configuration \
  --function-name iam-key-rotator-credential-rotator-security-lab \
  --environment 'Variables={DRY_RUN=true,ROTATION_AGE_DAYS=90,SNS_TOPIC_ARN=<topic-arn>,SECRET_PREFIX=iam/access-keys,PROTECTED_USERS=[]}' \
  --profile security

# Invoke
aws lambda invoke \
  --function-name iam-key-rotator-credential-rotator-security-lab \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile security \
  /tmp/dry-run-output.json

cat /tmp/dry-run-output.json | python3 -m json.tool
```

Expected response — stale keys listed under `skipped` with `"reason": "dry_run"`, nothing under `rotated`:

```json
{
  "rotated": [],
  "skipped": [
    { "user": "alice", "key": "AKIAIOSFODNN7EXAMPLE", "reason": "dry_run" }
  ],
  "errors": [],
  "notified": [
    { "user": "alice", "key": "AKIAIOSFODNN7EXAMPLE" }
  ]
}
```

Reset dry run to `false` after the test.

---

### Test 3 — SNS notification received

Invoke the Lambda manually against a test IAM user whose key is older than 90 days:

```bash
aws lambda invoke \
  --function-name iam-key-rotator-credential-rotator-security-lab \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile security \
  /tmp/rotation-output.json

cat /tmp/rotation-output.json | python3 -m json.tool
```

Check the configured email inbox. The notification subject is:

```
[IAM Key Rotation] Action required for <username>
```

---

### Test 4 — Verify old key is deleted after rotation

Before invoking, note the key ID of the stale key:

```bash
aws iam list-access-keys --user-name <username> --profile security
```

After the Lambda returns, confirm the old key no longer exists:

```bash
aws iam list-access-keys --user-name <username> --profile security
```

Expected: the old key ID is absent; a new key ID appears in its place.

---

### Test 5 — New credentials stored in Secrets Manager

```bash
aws secretsmanager get-secret-value \
  --secret-id iam/access-keys/<username> \
  --profile security \
  --query SecretString \
  --output text | python3 -m json.tool
```

Expected response:

```json
{
  "AccessKeyId": "AKIANEWKEYEXAMPLE",
  "SecretAccessKey": "...",
  "UserName": "<username>",
  "RotatedAt": "2026-05-27T00:00:00+00:00"
}
```

---

### Test 6 — Protected user is not rotated

Add a username to `protected_users` in `terraform.tfvars`, apply, then invoke the Lambda. The response should show that user under `skipped` with `"reason": "protected"` and no SNS notification sent for them.

---

## Monitoring and Alerts

| Signal | What it means | Where to look |
|---|---|---|
| SNS email — `[IAM Key Rotation] Action required for …` | A key exceeded the age threshold and rotation started | Inbox |
| `rotated` entries in Lambda response | Keys successfully rotated this run | Lambda invocation response / CloudWatch Logs |
| `errors` entries in Lambda response | A user's key could not be rotated | CloudWatch Logs (`/aws/lambda/iam-key-rotator-credential-rotator-security-lab`) |
| `skipped` with `reason: protected` | User is in the protected list — no action taken | CloudWatch Logs |
| Secrets Manager `PutSecretValue` event | New credentials written after successful rotation | CloudTrail |

Query recent rotation activity in CloudWatch Logs Insights:

```
fields @timestamp, @message
| filter @message like /rotated|error|protected/
| sort @timestamp desc
| limit 50
```

Query CloudTrail for all key deletions performed by the Lambda role:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteAccessKey \
  --region us-east-1 \
  --profile security \
  --query 'Events[*].{Time:EventTime,User:Username,Key:CloudTrailEvent}' \
  --output table
```
