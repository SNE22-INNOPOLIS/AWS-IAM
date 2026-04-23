variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "security_account_id" {
  description = "Security account ID"
  type        = string
}

variable "dev_account_id" {
  description = "Dev account ID"
  type        = string
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