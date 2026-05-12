# =============================================================================
# Terraform Variables - Lab 3
# =============================================================================

# AWS Account IDs
security_account_id = "865147226759"
dev_account_id      = "418272768233"

# AWS CLI Profiles
security_account_profile = "security"
dev_account_profile      = "dev"

# Region
primary_region = "us-east-1"

# Project Settings
project_name = "iam-guardrails"
environment  = "security-lab"
cloudtrail_bucket_name = "security-lab-central-cloudtrail-logs"

# Break Glass Configuration
breakglass_users = [
   "arn:aws:iam::865147226759:user/rolly"
]

security_breakglass_group_name = "Administrators"
dev_breakglass_group_name      = ""   

# Notifications
notification_email = "rollymk22@outlook.com"

# Guardrail Settings
enable_auto_remediation = true
protected_resources     = ["*"]

# Lab 1 & 2 Settings (keep existing)
unused_permission_threshold_days = 90
lambda_schedule_expression       = "rate(7 days)"
enable_scheduled_execution       = true
enable_sns_notifications         = true
create_test_roles                = true