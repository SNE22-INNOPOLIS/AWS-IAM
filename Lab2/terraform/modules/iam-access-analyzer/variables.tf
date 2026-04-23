variable "analyzer_name" {
  description = "Name of the IAM Access Analyzer"
  type        = string
}

variable "analyzer_type" {
  description = "Type of analyzer (ACCOUNT or ORGANIZATION)"
  type        = string
  default     = "ACCOUNT"

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.analyzer_type)
    error_message = "Analyzer type must be either ACCOUNT or ORGANIZATION."
  }
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "tags" {
  description = "Additional tags for the analyzer"
  type        = map(string)
  default     = {}
}