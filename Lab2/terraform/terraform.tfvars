# =============================================================================
# Terraform Variables Example
# Copy this file to terraform.tfvars and update with your values
# =============================================================================

# AWS Account IDs
security_account_id = "111111111111"
dev_account_id      = "222222222222"

# AWS CLI Profiles
security_account_profile = "security"
dev_account_profile      = "dev"

# Region Configuration
primary_region    = "us-east-1"
secondary_regions = ["us-west-2"]

# IAM Audit Configuration
unused_permission_threshold_days = 90
lambda_schedule_expression       = "rate(7 days)"
enable_scheduled_execution       = true

# Notification Settings
enable_sns_notifications = true
notification_email       = "b3tvvuk2qd@ruutukf.com"

# Test Configuration
create_test_roles = true

# Project Settings
project_name = "iam-audit"
environment  = "security-lab"