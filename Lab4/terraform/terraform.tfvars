security_account_id        = "865147226759"
security_account_profile   = "security"
primary_region             = "us-east-1"
project_name               = "iam-key-rotator"
notification_email         = "mailtosamsoni@gmail.com"
rotation_age_days          = 90
lambda_schedule_expression = "rate(7 days)"
enable_dry_run             = false
protected_users            = []
secret_prefix              = "iam/access-keys"

# Lambda runtime configuration
lambda_runtime     = "python3.12"
lambda_timeout     = 300
lambda_memory_size = 256
log_retention_days = 30

# Encryption
kms_key_alias = "alias/aws/sns"

