# =============================================================================
# Provider Configuration for Multi-Account Security Lab
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

# Primary account provider (Security/Audit account)
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      Project     = "SecurityLab"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Purpose     = "IAM-Permission-Analysis"
    }
  }
}

# Provider for secondary account (if using cross-account)
provider "aws" {
  alias  = "member_account_1"
  region = var.primary_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.member_account_ids[0]}:role/${var.cross_account_role_name}"
    session_name = "TerraformSecurityLab"
  }

  default_tags {
    tags = {
      Project     = "SecurityLab"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Provider for third account (if using cross-account)
provider "aws" {
  alias  = "member_account_2"
  region = var.primary_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.member_account_ids[1]}:role/${var.cross_account_role_name}"
    session_name = "TerraformSecurityLab"
  }

  default_tags {
    tags = {
      Project     = "SecurityLab"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}