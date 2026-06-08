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

variable "quicksight_user_arn" {
  type        = string
  description = "ARN of the QuickSight user that owns the data source and datasets"
}

variable "quicksight_namespace" {
  type        = string
  default     = "default"
  description = "QuickSight namespace"
}

variable "glue_database_name" {
  type        = string
  description = "Glue catalog database name used in Athena SQL queries"
}

variable "athena_workgroup_name" {
  type        = string
  description = "Athena workgroup to execute dataset queries against"
}

variable "findings_bucket_name" {
  type        = string
  description = "S3 bucket name for findings data and Athena query results"
}

variable "findings_bucket_arn" {
  type        = string
  description = "ARN of the findings S3 bucket (used in IAM policy)"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources in this module"
}
