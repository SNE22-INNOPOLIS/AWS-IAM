variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "account_name" {
  description = "Account name (security or dev)"
  type        = string
}

variable "reports_bucket_name" {
  description = "Name of the S3 bucket for reports"
  type        = string
}

variable "reports_bucket_arn" {
  description = "ARN of the S3 bucket for reports"
  type        = string
}

variable "unused_threshold_days" {
  description = "Number of days to consider permission as unused"
  type        = number
  default     = 90
}

variable "enable_scheduled_execution" {
  description = "Enable scheduled execution"
  type        = bool
  default     = true
}

variable "schedule_expression" {
  description = "Schedule expression for EventBridge"
  type        = string
  default     = "rate(7 days)"
}

variable "enable_sns_notifications" {
  description = "Enable SNS notifications"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email for notifications"
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "ARN of SNS topic for notifications"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cross_account_bucket" {
  description = "Whether the bucket is in a different account"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}