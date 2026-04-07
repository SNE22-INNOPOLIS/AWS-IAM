variable "trail_name" {
  type = string
}

variable "s3_bucket_name" {
  type = string
}

variable "account_id" {
  type = string
}

variable "enable_multi_region" {
  type    = bool
  default = true
}