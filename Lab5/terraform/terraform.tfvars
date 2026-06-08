# =========================================================
# Lab 5 — IAM Health Dashboard
# Fill in the values marked with TODO before running apply.
# =========================================================

security_account_id      = "TODO: 123456789012"
security_account_profile = "security"
primary_region           = "us-east-1"
project_name             = "iam-dashboard"

# ARN of the IAM Access Analyzer created in Lab 2.
# Leave as "" to skip Access Analyzer findings collection.
analyzer_arn = "TODO: arn:aws:access-analyzer:us-east-1:123456789012:analyzer/iam-access-analyzer"

# Access key rotation threshold from Lab 4 (kept consistent).
key_age_threshold_days = 90

# Daily schedule — aggregator runs at 01:00 UTC, crawler at 02:00 UTC.
lambda_schedule_expression = "cron(0 1 * * ? *)"
glue_crawler_schedule      = "cron(0 2 * * ? *)"

# QuickSight user ARN. Find it with:
#   aws quicksight list-users --aws-account-id <id> --namespace default --profile security
quicksight_user_arn   = "TODO: arn:aws:quicksight:us-east-1:123456789012:user/default/your-username"
quicksight_namespace  = "default"

# Retention
log_retention_days      = 30
findings_retention_days = 365

# Athena query cost guard: 1 GB maximum bytes scanned per query.
athena_bytes_scanned_cutoff = 1073741824

# Lambda
lambda_runtime     = "python3.12"
lambda_timeout     = 900
lambda_memory_size = 512
