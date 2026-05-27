# Lab 4 — Automated IAM Access Key Rotation

Enforces automatic rotation for all IAM user access keys. A weekly Lambda identifies keys older than 90 days, sends an SNS notice before and after rotation, stores the new key in Secrets Manager, and deletes the old one.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Security Account                         │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │          EventBridge  ·  rate(7 days)                │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼──────────────────────────────┐   │
│  │         Lambda: credential-rotator                    │   │
│  │  1. List IAM users                                    │   │
│  │  2. Find Active keys older than 90 days               │   │
│  │  3. Send pre-rotation SNS notice                      │   │
│  │  4. Create new key → store in Secrets Manager         │   │
│  │  5. Delete old key → send completion SNS notice       │   │
│  └───┬───────────────────┬───────────────────────┬──────┘   │
│      ▼                   ▼                        ▼           │
│  ┌───────┐   ┌────────────────────┐   ┌──────────────────┐  │
│  │  IAM  │   │  Secrets Manager   │   │    SNS Topic     │  │
│  └───────┘   │  iam/access-keys/  │   └────────┬─────────┘  │
│              │  <username>        │            │             │
│              └────────────────────┘            ▼             │
└───────────────────────────────────── Security Team Email ────┘
```

## How It Works

For each IAM user, any **Active** key older than `ROTATION_AGE_DAYS` is rotated:

1. SNS pre-rotation email — key ID, age, and Secrets Manager path
2. New key created → stored at `iam/access-keys/<username>` in Secrets Manager → old key deleted
3. SNS completion email — new key ID and `aws secretsmanager get-secret-value` retrieval command
4. Users in `protected_users` are skipped entirely

IAM limits each user to 2 keys. If both slots are full, the Lambda deletes an existing inactive key first; if none exists, it deactivates the stale key to make room before creating the replacement.

---

## Module Structure

```
Lab4/
├── lambda/
│   └── credential-rotator/
│       ├── lambda_function.py
│       ├── requirements.txt
│       └── test_lambda.py
└── terraform/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    ├── providers.tf
    ├── backend.tf
    ├── terraform.tfvars
    └── modules/
        ├── notifications/
        └── key-rotator/
```

---

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI `security` profile configured
- S3 + DynamoDB Terraform backend (created in Lab 1)

---

## Configuration

All values are set in `terraform/terraform.tfvars`:

| Variable | Description | Default |
|---|---|---|
| `security_account_id` | Security account AWS ID | — |
| `security_account_profile` | AWS CLI named profile | `security` |
| `primary_region` | AWS region | `us-east-1` |
| `project_name` | Resource name prefix | `iam-key-rotator` |
| `notification_email` | Rotation alert email | — |
| `rotation_age_days` | Key age threshold (days) | `90` |
| `lambda_schedule_expression` | EventBridge schedule | `rate(7 days)` |
| `enable_dry_run` | Scan only, no rotation | `false` |
| `protected_users` | Usernames excluded from rotation | `[]` |
| `secret_prefix` | Secrets Manager path prefix | `iam/access-keys` |
| `lambda_runtime` | Python runtime | `python3.12` |
| `lambda_timeout` | Lambda timeout (seconds) | `300` |
| `lambda_memory_size` | Lambda memory (MB) | `256` |
| `log_retention_days` | CloudWatch log retention | `30` |
| `kms_key_alias` | KMS key for SNS encryption | `alias/aws/sns` |

---

## Deployment

```bash
cd Lab4/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Confirm the SNS subscription email immediately after apply** — AWS deletes unconfirmed subscriptions after 72 hours.

To run unit tests locally:

```bash
cd Lab4/lambda/credential-rotator
pip install -r requirements.txt
python -m pytest test_lambda.py -v
```

---

## Testing

| Test | Command |
|---|---|
| Dry run — find stale keys without rotating | Set `enable_dry_run = true`, apply, invoke Lambda |
| Manual invocation | `aws lambda invoke --function-name <name> --payload '{}' --cli-binary-format raw-in-base64-out --profile security out.json` |
| Verify old key deleted | `aws iam list-access-keys --user-name <username> --profile security` |
| Retrieve new credentials | `aws secretsmanager get-secret-value --secret-id iam/access-keys/<username> --profile security --query SecretString --output text` |
| Confirm protected user skipped | Add username to `protected_users`, apply, invoke — check `skipped` in response |

---

## Monitoring

| Signal | Meaning | Where |
|---|---|---|
| Email: `[IAM Key Rotation] Action required` | Key exceeded threshold, rotation starting | Inbox |
| Email: `[IAM Key Rotation] Complete` | Rotation done, new key ID + retrieval command | Inbox |
| `errors` in Lambda response | A user's key could not be rotated | CloudWatch Logs |
| `skipped` with `reason: protected` | User is on the protected list | CloudWatch Logs |
| `secretsmanager:PutSecretValue` event | New credentials written | CloudTrail |
