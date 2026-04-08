# =============================================================================
# IAM Audit Lambda Module Variables
# =============================================================================

variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "unused_threshold_days" {
  description = "Number of days to consider a service unused"
  type        = number
  default     = 90
}

variable "s3_bucket_name" {
  description = "S3 bucket for storing reports"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for notifications"
  type        = string
}

variable "schedule_expression" {
  description = "CloudWatch Events schedule expression"
  type        = string
  default     = "rate(7 days)"
}

variable "member_account_ids" {
  description = "List of member account IDs for cross-account auditing"
  type        = list(string)
  default     = []
}

variable "cross_account_role_name" {
  description = "Name of the role to assume in member accounts"
  type        = string
  default     = "IAMAuditCrossAccountRole"
}

variable "log_level" {
  description = "Logging level for Lambda function"
  type        = string
  default     = "INFO"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}