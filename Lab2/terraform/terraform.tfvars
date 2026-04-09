# =============================================================================
# Example Terraform Variables - Copy to terraform.tfvars and customize
# =============================================================================

# Your Security/Audit Account ID from Lab1
security_account_id = "865147226759"  # Replace with actual Security Account ID

# Your Workloads Account ID from Lab1
dev_account_id = "418272768233"  # Replace with actual Workloads Account ID

# Cross-account role name (must match Lab1 configuration)
cross_account_role_name = "CrossAccountAuditRole"

# External ID for cross-account role (must match Lab1 configuration)
cross_account_external_id = "security-lab-audit"

# =============================================================================
# Environment Configuration
# =============================================================================

environment    = "lab"
primary_region = "us-east-1"

# =============================================================================
# Access Analyzer Configuration
# =============================================================================

enable_access_analyzer = true
unused_threshold_days  = 90

# =============================================================================
# Lambda Configuration
# =============================================================================

lambda_schedule_expression = "rate(7 days)"
lambda_timeout             = 900
lambda_memory_size         = 512

# =============================================================================
# Notification Configuration
# =============================================================================

# Email for audit notifications (leave empty to skip email subscription)
notification_email = "olugbengasamsonidowu@gmail.com"

# =============================================================================
# S3 Configuration
# =============================================================================

# Leave empty for auto-generated bucket name
s3_report_bucket_name = ""

# Lifecycle configuration
s3_lifecycle_ia_days         = 90
s3_lifecycle_glacier_days    = 180
s3_lifecycle_expiration_days = 365

# =============================================================================
# Test Resources
# =============================================================================

create_test_roles = true

test_roles = [
  {
    name        = "TestRole-EC2Admin"
    description = "Test role with EC2 permissions - for audit demo"
    services    = ["ec2", "s3", "cloudwatch", "ssm"]
  },
  {
    name        = "TestRole-LambdaDev"
    description = "Test role with Lambda permissions - for audit demo"
    services    = ["lambda", "logs", "s3", "dynamodb", "sqs", "sns"]
  },
  {
    name        = "TestRole-DataAnalyst"
    description = "Test role with analytics permissions - for audit demo"
    services    = ["athena", "glue", "s3", "quicksight", "redshift"]
  }
]

# =============================================================================
# Additional Tags
# =============================================================================

tags = {
  Owner      = "SecurityTeam"
  CostCenter = "Security-Lab"
  Lab        = "Lab2"
}
