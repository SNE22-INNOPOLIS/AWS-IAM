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

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 900
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

# =============================================================================
# Cross-Account Configuration (From Lab1)
# =============================================================================

variable "security_account_id" {
  description = "Security Account ID"
  type        = string
}

variable "dev_account_id" {
  description = "Workloads Account ID"
  type        = string
}

variable "cross_account_role_name" {
  description = "Name of the role to assume in Workloads Account"
  type        = string
  default     = "CrossAccountAuditRole"
}

variable "cross_account_external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = "security-lab-audit"
}

# =============================================================================
# Logging
# =============================================================================

variable "log_level" {
  description = "Logging level for Lambda function"
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}