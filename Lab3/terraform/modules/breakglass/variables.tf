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

variable "breakglass_users" {
  description = "List of IAM user ARNs allowed to assume BreakGlass role"
  type        = list(string)
  default     = []
}

variable "cross_account_role_arn" {
  description = "ARN of cross-account BreakGlass role (for Dev account)"
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