variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "account_name" {
  description = "Account name"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "permission_boundary_arn" {
  description = "ARN of permission boundary to attach"
  type        = string
}

variable "enable_auto_remediation" {
  description = "Enable automatic remediation"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email for notifications"
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  type        = string
  default     = ""
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