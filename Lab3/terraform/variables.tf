# =============================================================================
# Variables Configuration - Lab 3
# =============================================================================

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "security_account_profile" {
  description = "AWS CLI profile for Security account"
  type        = string
  default     = "security"
}

variable "dev_account_profile" {
  description = "AWS CLI profile for Dev account"
  type        = string
  default     = "dev"
}

variable "security_account_id" {
  description = "AWS Account ID for Security account"
  type        = string
}

variable "dev_account_id" {
  description = "AWS Account ID for Dev account"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "iam-guardrails"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "security-lab"
}

variable "breakglass_users" {
  description = "List of IAM user ARNs allowed to assume BreakGlass role"
  type        = list(string)
  default     = []
}

variable "notification_email" {
  description = "Email for guardrail violation alerts"
  type        = string
  default     = ""
}

variable "enable_auto_remediation" {
  description = "Enable automatic attachment of permission boundaries"
  type        = bool
  default     = true
}

variable "protected_resources" {
  description = "List of resource ARNs that require MFA for deletion"
  type        = list(string)
  default     = ["*"]
}

# Lab 1 & 2 variables (keep existing infrastructure)
variable "unused_permission_threshold_days" {
  description = "Days threshold for unused permissions"
  type        = number
  default     = 90
}

variable "lambda_schedule_expression" {
  description = "Schedule for IAM audit Lambda"
  type        = string
  default     = "rate(7 days)"
}

variable "enable_scheduled_execution" {
  description = "Enable scheduled Lambda execution"
  type        = bool
  default     = true
}

variable "enable_sns_notifications" {
  description = "Enable SNS notifications"
  type        = bool
  default     = true
}

variable "create_test_roles" {
  description = "Create test IAM roles"
  type        = bool
  default     = true
}

variable "security_breakglass_group_name" {
  description = "Existing IAM group name in Security account for Break Glass access"
  type        = string
  default     = ""
}

variable "dev_breakglass_group_name" {
  description = "Existing IAM group name in Dev account for Break Glass access"
  type        = string
  default     = ""
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs (from Lab 1)"
  type        = string
}