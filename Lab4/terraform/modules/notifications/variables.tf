variable "project_name" {
  type        = string
  description = "Project name used as a resource name prefix"
}

variable "environment" {
  type        = string
  description = "Deployment environment label (e.g. security-lab)"
}

variable "notification_email" {
  type        = string
  description = "Email address that receives key-rotation notifications"
}

variable "kms_key_alias" {
  type        = string
  default     = "alias/aws/sns"
  description = "KMS key alias used to encrypt the SNS topic"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources in this module"
}
