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

# =============================================================================
# Security Account Provider (Primary - where audit resources are deployed)
# =============================================================================
provider "aws" {
  region = var.primary_region
  profile = "security"

  default_tags {
    tags = {
      Project     = "SecurityLab"
      Lab         = "Lab2-IAM-Audit"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Purpose     = "IAM-Permission-Analysis"
    }
  }
}

# =============================================================================
# Workloads Account Provider (For cross-account resources)
# =============================================================================
provider "aws" {
  alias  = "dev"
  region = var.primary_region

  assume_role {
    role_arn     = "arn:aws:iam::${var.dev_account_id}:role/${var.cross_account_role_name}"
    session_name = "TerraformLab2"
    external_id  = var.cross_account_external_id
  }

  default_tags {
    tags = {
      Project     = "SecurityLab"
      Lab         = "Lab2-IAM-Audit"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}