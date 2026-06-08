# Lab 5 — IAM Health Dashboard

Security findings are only actionable when stakeholders can see them. This lab builds an end-to-end pipeline that aggregates IAM findings from Security Hub and Access Analyzer, stores them in S3, makes them queryable via Athena, and surfaces three key metrics in an Amazon QuickSight dashboard.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                        Security Account                             │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │   EventBridge · cron(0 1 * * ? *)  [daily 01:00 UTC]        │  │
│  └────────────────────────┬─────────────────────────────────────┘  │
│                           │                                        │
│  ┌────────────────────────▼─────────────────────────────────────┐  │
│  │              Lambda: iam-findings-aggregator                  │  │
│  │  ┌──────────────┐ ┌─────────────┐ ┌──────────┐ ┌─────────┐  │  │
│  │  │ Security Hub │ │IAM Analyzer │ │ IAM API  │ │CloudTrl │  │  │
│  │  │ (IAM roles,  │ │(external    │ │(stale    │ │(SCP     │  │  │
│  │  │  users,      │ │ access      │ │ keys,    │ │ denies) │  │  │
│  │  │  policies)   │ │ findings)   │ │ unused   │ │         │  │  │
│  │  └──────┬───────┘ └──────┬──────┘ │ perms)   │ └────┬────┘  │  │
│  │         └────────────────┴────────┴──────┬───┘      │        │  │
│  └──────────────────────────────────────────┼──────────┘        │  │
│                                             │                    │  │
│  ┌──────────────────────────────────────────▼───────────────┐   │  │
│  │  S3: iam-dashboard-findings-<account>                    │   │  │
│  │  findings/security_hub_findings/year=.../month=.../...   │   │  │
│  │  findings/stale_access_keys/year=.../month=.../...       │   │  │
│  │  findings/unused_role_permissions/year=.../month=.../... │   │  │
│  │  findings/scp_violations/year=.../month=.../...          │   │  │
│  └────────────────────────┬─────────────────────────────────┘   │  │
│                           │                                       │  │
│  ┌────────────────────────▼─────────────────────────────────┐   │  │
│  │  Glue Crawler · cron(0 2 * * ? *)  [daily 02:00 UTC]    │   │  │
│  │  → Updates iam_health_db tables in Glue Catalog          │   │  │
│  └────────────────────────┬─────────────────────────────────┘   │  │
│                           │                                       │  │
│  ┌────────────────────────▼─────────────────────────────────┐   │  │
│  │  Athena Workgroup: iam-health-workgroup                  │   │  │
│  │  SQL queries → scripts/sql/                              │   │  │
│  └────────────────────────┬─────────────────────────────────┘   │  │
│                           │                                       │  │
│  ┌────────────────────────▼─────────────────────────────────┐   │  │
│  │  QuickSight Dashboard: "IAM Health Overview"             │   │  │
│  │  ┌──────────────────────┐  ┌──────────────────────────┐  │   │  │
│  │  │  KPI: % Roles with   │  │  KPI: Access Keys        │  │   │  │
│  │  │  Unused Permissions  │  │  > 90 Days Old           │  │   │  │
│  │  └──────────────────────┘  └──────────────────────────┘  │   │  │
│  │  ┌────────────────────────────────────────────────────┐  │   │  │
│  │  │  Line Chart: SCP Violation Attempts — Trend        │  │   │  │
│  │  └────────────────────────────────────────────────────┘  │   │  │
│  └──────────────────────────────────────────────────────────┘   │  │
└────────────────────────────────────────────────────────────────────┘
```

---

## How It Works

1. **EventBridge** triggers the `iam-findings-aggregator` Lambda daily at 01:00 UTC.
2. **Lambda** pulls findings from four sources:
   - **Security Hub** — active IAM findings (roles, users, policies)
   - **IAM Access Analyzer** — external access findings
   - **IAM API** — access keys older than `KEY_AGE_THRESHOLD_DAYS` (default 90), and unused service permissions per role via `GenerateServiceLastAccessedDetails`
   - **CloudTrail** — `AccessDenied` events where the error message references a Service Control Policy
3. Each category is written to S3 as **NDJSON** (one JSON object per line) under a Hive-partitioned prefix (`year=/month=/day=`).
4. **Glue Crawler** runs at 02:00 UTC, discovers new partitions, and updates the Glue Catalog tables in `iam_health_db`.
5. **Athena** queries are stored in `scripts/sql/` and power the QuickSight datasets.
6. **QuickSight** dashboard (`scripts/quicksight/`) is deployed with the `deploy_dashboard.sh` script after Terraform provisions the data source and datasets.

---

## Module Structure

```
Lab5/
├── docs/
│   └── dashboard/          ← Screenshots go here after first deploy
├── scripts/
│   ├── sql/                ← Athena SQL queries (acceptance criteria)
│   │   ├── 01_unused_permissions.sql
│   │   ├── 02_old_access_keys.sql
│   │   ├── 03_scp_violations.sql
│   │   └── 04_iam_health_summary.sql
│   ├── aggregator/         ← Lambda source code
│   │   ├── lambda_function.py
│   │   ├── requirements.txt
│   │   └── test_lambda.py
│   └── quicksight/         ← Dashboard-as-code
│       ├── dashboard_definition.json
│       └── deploy_dashboard.sh
└── terraform/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    ├── providers.tf
    ├── backend.tf
    ├── terraform.tfvars
    └── modules/
        ├── data-pipeline/      ← S3 bucket, Glue, Athena workgroup
        ├── security-hub-export/← Lambda + EventBridge trigger + IAM role
        └── quicksight/         ← QuickSight data source + datasets
```

---

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI with a `security` profile configured
- S3 + DynamoDB Terraform backend (created in Lab 1)
- Security Hub enabled in the account
- IAM Access Analyzer active (created in Lab 2)
- Amazon QuickSight Enterprise/Standard edition subscribed (manual one-time step)
- QuickSight execution role must have access to Athena and S3

---

## Configuration

All values are set in `terraform/terraform.tfvars`:

| Variable | Description | Default |
|---|---|---|
| `security_account_id` | AWS account ID | — |
| `security_account_profile` | AWS CLI named profile | `security` |
| `primary_region` | Deployment region | `us-east-1` |
| `project_name` | Resource name prefix | `iam-dashboard` |
| `analyzer_arn` | ARN of the IAM Access Analyzer from Lab 2 | — |
| `key_age_threshold_days` | Access key age threshold in days | `90` |
| `lambda_schedule_expression` | EventBridge schedule for aggregator | `cron(0 1 * * ? *)` |
| `glue_crawler_schedule` | Glue crawler schedule | `cron(0 2 * * ? *)` |
| `quicksight_user_arn` | ARN of the QuickSight user/principal | — |
| `log_retention_days` | CloudWatch log retention (days) | `30` |
| `findings_retention_days` | S3 findings retention (days) | `365` |

---

## Deployment

### Step 1 — Provision infrastructure

```bash
cd Lab5/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### Step 2 — Trigger first data collection

```bash
aws lambda invoke \
  --function-name iam-findings-aggregator \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile security \
  out.json
cat out.json
```

### Step 3 — Run Glue Crawler

```bash
aws glue start-crawler \
  --name iam-dashboard-crawler \
  --profile security
```

Wait until the crawler status is `READY` before deploying the dashboard.

### Step 4 — Deploy QuickSight dashboard

Edit `scripts/quicksight/deploy_dashboard.sh` and fill in the exported Terraform output values, then:

```bash
# Export Terraform outputs first
cd Lab5/terraform
terraform output -json > /tmp/lab5_outputs.json

# Deploy dashboard
cd ../scripts/quicksight
bash deploy_dashboard.sh
```

### Step 5 — Take screenshots

Open the QuickSight dashboard URL printed by the deploy script, capture screenshots, and save them to `docs/dashboard/`.

---

## SQL Queries

| File | Metric | Athena Table |
|---|---|---|
| `01_unused_permissions.sql` | % Roles with unused permissions (daily snapshot) | `iam_health_db.unused_role_permissions` |
| `02_old_access_keys.sql` | Count of active keys older than 90 days | `iam_health_db.stale_access_keys` |
| `03_scp_violations.sql` | SCP violation attempts (daily count + detail) | `iam_health_db.scp_violations` |
| `04_iam_health_summary.sql` | Combined health scorecard across all metrics | all tables |

---

## Dashboard Visuals

| Visual | Type | Dataset | Description |
|---|---|---|---|
| % Roles with Unused Permissions | KPI | `unused_permissions_daily` | Percentage of non-service roles that have at least one never-used IAM service in the last 90 days |
| Access Keys > 90 Days Old | KPI | `stale_keys_daily` | Count of currently active access keys whose age exceeds the rotation threshold |
| SCP Violation Attempts | Line Chart | `scp_violations_daily` | Daily count of CloudTrail `AccessDenied` events caused by Service Control Policies — trend over 30 days |

---

## Testing

| Test | Command |
|---|---|
| Unit tests | `cd Lab5/scripts/aggregator && pip install -r requirements.txt && python -m pytest test_lambda.py -v` |
| Manual Lambda invoke | `aws lambda invoke --function-name iam-findings-aggregator --payload '{}' --cli-binary-format raw-in-base64-out --profile security out.json` |
| Verify S3 output | `aws s3 ls s3://<bucket>/findings/ --recursive --profile security \| head -20` |
| Test Athena query | Run `scripts/sql/04_iam_health_summary.sql` in the Athena console against workgroup `iam-health-workgroup` |
| Verify QuickSight dataset | Open QuickSight → Datasets → `stale_keys_daily` → Edit → Preview |

---

## Monitoring

| Signal | Meaning | Where |
|---|---|---|
| Lambda ERROR in CloudWatch | Aggregator failed for a category | CloudWatch Logs `/aws/lambda/iam-findings-aggregator` |
| Glue Crawler state `FAILED` | Schema detection failed | Glue console → Crawlers |
| Empty Athena result | Crawler hasn't run yet, or Lambda failed | Re-run crawler after Lambda invoke |
| QuickSight dataset refresh error | Athena query failed or permissions missing | QuickSight → Datasets → error icon |
