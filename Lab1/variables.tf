variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "security_profile" {
  description = "AWS CLI profile for Security account"
  type        = string
}

variable "dev_profile" {
  description = "AWS CLI profile for Dev account"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Centralized CloudTrail bucket in Security account"
  type        = string
}

variable "config_bucket_name" {
  description = "Centralized AWS Config bucket in Security account"
  type        = string
}

variable "trail_name_security" {
  description = "CloudTrail name in Security account"
  type        = string
  default     = "security-account-trail"
}

variable "trail_name_dev" {
  description = "CloudTrail name in Dev account"
  type        = string
  default     = "dev-account-trail"
}

variable "config_recorder_name_security" {
  type    = string
  default = "security-config-recorder"
}

variable "config_recorder_name_dev" {
  type    = string
  default = "dev-config-recorder"
}