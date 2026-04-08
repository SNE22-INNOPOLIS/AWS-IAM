# =============================================================================
# Access Analyzer Module Variables
# =============================================================================

variable "analyzer_name" {
  description = "Name of the IAM Access Analyzer"
  type        = string
}

variable "analyzer_type" {
  description = "Type of analyzer: ACCOUNT or ORGANIZATION"
  type        = string
  default     = "ACCOUNT"

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION", "ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"], var.analyzer_type)
    error_message = "analyzer_type must be ACCOUNT, ORGANIZATION, ACCOUNT_UNUSED_ACCESS, or ORGANIZATION_UNUSED_ACCESS"
  }
}

variable "enable_unused_access_analyzer" {
  description = "Enable unused access analyzer"
  type        = bool
  default     = true
}

variable "unused_access_age" {
  description = "Number of days to consider access unused"
  type        = number
  default     = 90
}

variable "enable_auto_archive" {
  description = "Enable auto-archive rules for known findings"
  type        = bool
  default     = false
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}