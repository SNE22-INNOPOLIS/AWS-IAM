# =============================================================================
# Terraform Providers Configuration
# Lab 3: IAM Preventative Guardrails
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# Security Account Provider
provider "aws" {
  alias   = "security"
  region  = var.primary_region
  profile = var.security_account_profile

  default_tags {
    tags = {
      Project     = "IAM-Guardrails-Lab"
      Environment = "Security"
      ManagedBy   = "Terraform"
      Lab         = "Lab3-Guardrails"
    }
  }
}

# Dev Account Provider
provider "aws" {
  alias   = "dev"
  region  = var.primary_region
  profile = var.dev_account_profile

  default_tags {
    tags = {
      Project     = "IAM-Guardrails-Lab"
      Environment = "Dev"
      ManagedBy   = "Terraform"
      Lab         = "Lab3-Guardrails"
    }
  }
}