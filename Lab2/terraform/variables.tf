# =============================================================================
# Variables Configuration
# =============================================================================

variable "primary_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "secondary_regions" {
  description = "Additional regions for Access Analyzer deployment"
  type        = list(string)
  default     = ["us-west-2"]
}

variable "security_account_profile" {
  description = "AWS CLI profile for the Security (Management) account"
  type        = string
  default     = "security"
}

variable "dev_account_profile" {
  description = "AWS CLI profile for the Dev account"
  type        = string
  default     = "dev"
}

variable "security_account_id" {
  description = "AWS Account ID for the Security account"
  type        = string
}

variable "dev_account_id" {
  description = "AWS Account ID for the Dev account"
  type        = string
}

variable "unused_permission_threshold_days" {
  description = "Number of days to consider a permission as unused"
  type        = number
  default     = 90
}

variable "lambda_schedule_expression" {
  description = "CloudWatch Events schedule expression for Lambda execution"
  type        = string
  default     = "rate(7 days)"
}

variable "enable_scheduled_execution" {
  description = "Enable scheduled execution of the IAM audit Lambda"
  type        = bool
  default     = true
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "iam-audit"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "security-lab"
}

# SNS notification settings
variable "enable_sns_notifications" {
  description = "Enable SNS notifications for audit reports"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for SNS notifications"
  type        = string
  default     = ""
}

# Test role settings for acceptance criteria validation
variable "create_test_roles" {
  description = "Create test IAM roles for validation"
  type        = bool
  default     = true
}