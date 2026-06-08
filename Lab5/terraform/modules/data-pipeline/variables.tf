variable "project_name" {
  type        = string
  description = "Resource name prefix"
}

variable "account_id" {
  type        = string
  description = "AWS account ID (appended to bucket name for global uniqueness)"
}

variable "glue_crawler_schedule" {
  type        = string
  description = "Cron schedule for the Glue crawler"
}

variable "findings_retention_days" {
  type        = number
  description = "Days before S3 findings objects are expired"
}

variable "athena_bytes_scanned_cutoff" {
  type        = number
  description = "Maximum bytes scanned per Athena query"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources in this module"
}
