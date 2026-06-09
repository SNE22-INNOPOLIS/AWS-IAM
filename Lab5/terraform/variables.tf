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
  description = "Primary AWS region for all resource deployment"
}

variable "project_name" {
  type        = string
  default     = "iam-dashboard"
  description = "Prefix applied to all resource names created by this lab"
}

variable "analyzer_arn" {
  type        = string
  default     = ""
  description = "ARN of the IAM Access Analyzer created in Lab 2; leave empty to skip Access Analyzer collection"
}

variable "key_age_threshold_days" {
  type        = number
  default     = 90
  description = "Access keys Active for longer than this many days are considered stale"
}

variable "lambda_schedule_expression" {
  type        = string
  default     = "cron(0 1 * * ? *)"
  description = "EventBridge schedule expression for the findings aggregator Lambda (UTC)"
}

variable "glue_crawler_schedule" {
  type        = string
  default     = "cron(0 2 * * ? *)"
  description = "Schedule for the Glue crawler (UTC); must run after the Lambda"
}

variable "quicksight_user_arn" {
  type        = string
  description = "ARN of the QuickSight IAM user or role that will own the data source and datasets"
}

variable "quicksight_namespace" {
  type        = string
  default     = "default"
  description = "QuickSight namespace (almost always 'default')"
}

variable "log_retention_days" {
  type        = number
  default     = 30
  description = "Retention period in days for Lambda CloudWatch log groups"
}

variable "findings_retention_days" {
  type        = number
  default     = 365
  description = "Days to retain findings objects in S3 before expiration"
}

variable "athena_bytes_scanned_cutoff" {
  type        = number
  default     = 1073741824
  description = "Maximum bytes scanned per Athena query (default 1 GB); protects against expensive full-table scans"
}

variable "lambda_runtime" {
  type        = string
  default     = "python3.12"
  description = "Python runtime version for the Lambda aggregator"
}

variable "lambda_timeout" {
  type        = number
  default     = 900
  description = "Lambda timeout in seconds (max 900); unused-permissions collection can be slow on large accounts"
}

variable "lambda_memory_size" {
  type        = number
  default     = 512
  description = "Memory allocated to the Lambda function in MB"
}

variable "enable_quicksight" {
  type        = bool
  default     = false
  description = "Set to true only after subscribing to QuickSight in this account (Console → QuickSight → Sign up). Deploying before subscription returns ResourceNotFoundException."
}

variable "quicksight_service_role_name" {
  type        = string
  default     = "aws-quicksight-service-role-v0"
  description = "Name of the IAM role QuickSight auto-creates on first sign-up. Find it with: aws iam list-roles --query 'Roles[?contains(RoleName,`quicksight`)].RoleName' --profile security"
}
