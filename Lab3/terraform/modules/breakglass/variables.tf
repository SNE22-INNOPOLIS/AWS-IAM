variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "account_name" {
  description = "Account name"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "breakglass_users" {
  description = "List of IAM user ARNs allowed to assume BreakGlass role"
  type        = list(string)
  default     = []
}

variable "cross_account_role_arn" {
  description = "ARN of cross-account BreakGlass role (for Dev account)"
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "ARN of SNS topic for alerts"  # <-- ADD THIS
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

variable "existing_group_name" {
  description = "Name of the existing IAM group to grant Break Glass access"
  type        = string
  default     = ""
}

variable "notification_email" {
  description = "Email address for Break Glass alerts"  # <-- THIS WAS MISSING
  type        = string
  default     = ""
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs from Lab 1"
  type        = string
}