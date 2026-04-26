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

variable "protected_resources" {
  description = "List of resource ARNs requiring MFA for deletion"
  type        = list(string)
  default     = ["*"]
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