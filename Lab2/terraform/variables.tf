# =============================================================================
# Variables for Multi-Account Security Lab
# =============================================================================

variable "environment" {
  description = "Environment name (e.g., lab, dev, staging)"
  type        = string
  default     = "lab"
}

variable "primary_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "additional_regions" {
  description = "Additional regions for Access Analyzer (for organization-level analysis)"
  type        = list(string)
  default     = ["us-west-2", "eu-west-1"]
}

variable "security_account_id" {
  description = "AWS Account ID of the security/audit account"
  type        = string
}

variable "member_account_ids" {
  description = "List of member account IDs to analyze"
  type        = list(string)
  default     = []
}

variable "cross_account_role_name" {
  description = "Name of the cross-account role for Terraform to assume"
  type        = string
  default     = "SecurityLabCrossAccountRole"
}

variable "enable_organization_analyzer" {
  description = "Enable organization-level Access Analyzer (requires AWS Organizations)"
  type        = bool
  default     = false
}

variable "unused_threshold_days" {
  description = "Number of days to consider a service unused"
  type        = number
  default     = 90
}

variable "lambda_schedule_expression" {
  description = "CloudWatch Events schedule expression for Lambda"
  type        = string
  default     = "rate(7 days)"
}

variable "notification_email" {
  description = "Email address for audit report notifications"
  type        = string
  default     = ""
}

variable "s3_report_bucket_name" {
  description = "S3 bucket name for storing audit reports"
  type        = string
  default     = ""
}

variable "test_roles_to_create" {
  description = "List of test IAM roles to create for demonstration"
  type = list(object({
    name        = string
    description = string
    services    = list(string)
  }))
  default = [
    {
      name        = "TestRole-EC2Admin"
      description = "Test role with EC2 permissions for demo"
      services    = ["ec2", "s3", "cloudwatch"]
    },
    {
      name        = "TestRole-LambdaDev"
      description = "Test role with Lambda permissions for demo"
      services    = ["lambda", "logs", "s3", "dynamodb"]
    }
  ]
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}