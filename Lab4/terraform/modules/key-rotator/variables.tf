variable "project_name" {
  type        = string
  description = "Project name used as a resource name prefix"
}

variable "environment" {
  type        = string
  description = "Deployment environment label (e.g. security-lab)"
}

variable "aws_region" {
  type        = string
  description = "AWS region where resources are deployed"
}

variable "account_id" {
  type        = string
  description = "AWS account ID where resources are deployed"
}

variable "lambda_source_dir" {
  type        = string
  description = "Absolute path to the Lambda function source directory"
}

variable "rotation_age_days" {
  type        = number
  default     = 90
  description = "Keys older than this many days (and still Active) will be rotated"
}

variable "schedule_expression" {
  type        = string
  default     = "rate(7 days)"
  description = "EventBridge schedule expression for the rotation trigger"
}

variable "sns_topic_arn" {
  type        = string
  description = "ARN of the SNS topic used for pre-rotation notifications"
}

variable "secret_prefix" {
  type        = string
  default     = "iam/access-keys"
  description = "Secrets Manager path prefix under which rotated keys are stored"
}

variable "protected_users" {
  type        = list(string)
  default     = []
  description = "IAM usernames that are excluded from automatic key rotation"
}

variable "dry_run" {
  type        = bool
  default     = false
  description = "When true, the Lambda identifies stale keys but does not rotate them"
}

variable "lambda_runtime" {
  type        = string
  default     = "python3.12"
  description = "Python runtime version for the Lambda function"
}

variable "lambda_timeout" {
  type        = number
  default     = 300
  description = "Maximum execution time in seconds for the Lambda function"
}

variable "lambda_memory_size" {
  type        = number
  default     = 256
  description = "Memory allocated to the Lambda function in MB"
}

variable "log_retention_days" {
  type        = number
  default     = 30
  description = "Number of days to retain Lambda execution logs in CloudWatch"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources in this module"
}
