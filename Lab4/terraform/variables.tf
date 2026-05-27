variable "security_account_id" {
  type        = string
  description = "AWS account ID for the security account"
}

variable "security_account_profile" {
  type        = string
  description = "AWS CLI named profile for the security account"
}

variable "primary_region" {
  type        = string
  default     = "us-east-1"
  description = "Primary AWS region for resource deployment"
}

variable "project_name" {
  type        = string
  default     = "iam-key-rotator"
  description = "Project name used as a prefix for all resource names"
}

variable "notification_email" {
  type        = string
  description = "Email address that receives pre-rotation and summary notifications"
}

variable "rotation_age_days" {
  type        = number
  default     = 90
  description = "Active keys older than this threshold (in days) will be rotated"
}

variable "lambda_schedule_expression" {
  type        = string
  default     = "rate(7 days)"
  description = "EventBridge schedule expression controlling how often the rotator runs"
}

variable "enable_dry_run" {
  type        = bool
  default     = false
  description = "When true, the Lambda reports stale keys without performing rotation"
}

variable "protected_users" {
  type        = list(string)
  default     = []
  description = "List of IAM usernames that are excluded from automatic key rotation"
}

variable "secret_prefix" {
  type        = string
  default     = "iam/access-keys"
  description = "Secrets Manager path prefix under which rotated credentials are stored"
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

variable "kms_key_alias" {
  type        = string
  default     = "alias/aws/sns"
  description = "KMS key alias used to encrypt the SNS topic"
}
