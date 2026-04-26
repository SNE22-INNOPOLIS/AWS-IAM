# =============================================================================
# Terraform Variables - Lab 3
# =============================================================================

# AWS Account IDs
security_account_id = "111111111111"
dev_account_id      = "222222222222"

# AWS CLI Profiles
security_account_profile = "security"
dev_account_profile      = "dev"

# Region
primary_region = "us-east-1"

# Project Settings
project_name = "iam-guardrails"
environment  = "security-lab"

# Break Glass Configuration
breakglass_users = [
  # "arn:aws:iam::111111111111:user/admin-user"
]

# Notifications
notification_email = "security-team@example.com"

# Guardrail Settings
enable_auto_remediation = true
protected_resources     = ["*"]

# Lab 1 & 2 Settings (keep existing)
unused_permission_threshold_days = 90
lambda_schedule_expression       = "rate(7 days)"
enable_scheduled_execution       = true
enable_sns_notifications         = true
create_test_roles                = true