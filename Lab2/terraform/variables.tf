# =============================================================================
# Variables for Multi-Account Security Lab
# =============================================================================

variable "security_account_id" {
  description = "AWS Account ID of the Security/Audit account (from Lab1)"
  type        = string
}

variable "dev_account_id" {
  description = "AWS Account ID of the Workloads account (from Lab1)"
  type        = string
}

variable "cross_account_role_name" {
  description = "Name of cross-account role created in Lab1"
  type        = string
  default     = "CrossAccountAuditRole"
}

variable "cross_account_external_id" {
  description = "External ID for cross-account role assumption (from Lab1)"
  type        = string
  default     = "security-lab-audit"
}

# =============================================================================
# Environment Configuration
# =============================================================================

variable "environment" {
  description = "Environment name (e.g., lab, dev, staging)"
  type        = string
  default     = "lab"
}

variable "primary_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

# =============================================================================
# Access Analyzer Configuration
# =============================================================================

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "unused_threshold_days" {
  description = "Number of days to consider a service unused"
  type        = number
  default     = 90
}

# =============================================================================
# Lambda Configuration
# =============================================================================

variable "lambda_schedule_expression" {
  description = "CloudWatch Events schedule expression for Lambda"
  type        = string
  default     = "rate(7 days)"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 900
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

# =============================================================================
# Notification Configuration
# =============================================================================

variable "notification_email" {
  description = "Email address for audit report notifications"
  type        = string
  default     = ""
}

# =============================================================================
# S3 Configuration
# =============================================================================

variable "s3_report_bucket_name" {
  description = "S3 bucket name for storing audit reports (leave empty for auto-generated name)"
  type        = string
  default     = ""
}

variable "s3_lifecycle_ia_days" {
  description = "Days before transitioning reports to Standard-IA"
  type        = number
  default     = 90
}

variable "s3_lifecycle_glacier_days" {
  description = "Days before transitioning reports to Glacier"
  type        = number
  default     = 180
}

variable "s3_lifecycle_expiration_days" {
  description = "Days before expiring reports"
  type        = number
  default     = 365
}

# =============================================================================
# Test Resources Configuration
# =============================================================================

variable "create_test_roles" {
  description = "Create test IAM roles for demonstration"
  type        = bool
  default     = true
}

variable "test_roles" {
  description = "List of test IAM roles to create for demonstration"
  type = list(object({
    name        = string
    description = string
    services    = list(string)
  }))
  default = [
    {
      name        = "TestRole-EC2Admin"
      description = "Test role with EC2 permissions for demo"
      services    = ["ec2", "s3", "cloudwatch"]
    },
    {
      name        = "TestRole-LambdaDev"
      description = "Test role with Lambda permissions for demo"
      services    = ["lambda", "logs", "s3", "dynamodb"]
    }
  ]
}

# =============================================================================
# Tags
# =============================================================================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
