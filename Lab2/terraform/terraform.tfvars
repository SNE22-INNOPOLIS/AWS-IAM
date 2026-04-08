# =============================================================================
# Example Terraform Variables - Copy to terraform.tfvars and customize
# =============================================================================

environment         = "lab"
primary_region      = "us-east-1"
additional_regions  = ["us-west-2"]
security_account_id = "123456789012"  # Replace with your account ID

# Uncomment for multi-account setup
# member_account_ids      = ["234567890123", "345678901234"]
# cross_account_role_name = "SecurityLabCrossAccountRole"

# Organization-level analyzer (requires AWS Organizations)
enable_organization_analyzer = false

# Audit settings
unused_threshold_days      = 90
lambda_schedule_expression = "rate(7 days)"

# Notifications
notification_email = "security-team@example.com"

# Test roles for demonstration
test_roles_to_create = [
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

tags = {
  Owner      = "SecurityTeam"
  CostCenter = "Security-123"
}