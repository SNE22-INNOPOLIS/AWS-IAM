variable "project_name" {
  type        = string
  description = "Resource name prefix"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "lambda_source_dir" {
  type        = string
  description = "Local path to the directory containing the Lambda source code"
}

variable "findings_bucket_name" {
  type        = string
  description = "S3 bucket name for writing NDJSON findings"
}

variable "findings_bucket_arn" {
  type        = string
  description = "ARN of the findings S3 bucket (used in IAM policy)"
}

variable "analyzer_arn" {
  type        = string
  description = "ARN of the IAM Access Analyzer; empty string disables Access Analyzer collection"
}

variable "key_age_threshold_days" {
  type        = number
  description = "Days after which an Active access key is considered stale"
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression for the Lambda trigger"
}

variable "lambda_runtime" {
  type        = string
  description = "Python runtime version for the Lambda function"
}

variable "lambda_timeout" {
  type        = number
  description = "Lambda execution timeout in seconds"
}

variable "lambda_memory_size" {
  type        = number
  description = "Lambda memory allocation in MB"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources in this module"
}
