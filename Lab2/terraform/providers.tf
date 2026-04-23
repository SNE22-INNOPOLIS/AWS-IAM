# =============================================================================
# Terraform Providers Configuration
# Multi-account setup with Security (Management) and Dev accounts
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
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }

  # Use the backend from Lab1
  backend "s3" {
    bucket         = "security-lab-tfstate-security-account"
    key            = "security-lab/lab2/terraform.tfstate"
    region         = "us-east-1"
    profile        = "security"
    encrypt        = true
    dynamodb_table = "security-lab-tf-locks"
  }
}

# Security Account Provider (Management Account)
provider "aws" {
  alias   = "security"
  region  = var.primary_region
  profile = var.security_account_profile

  default_tags {
    tags = {
      Project     = "IAM-Access-Analyzer-Lab"
      Environment = "Security"
      ManagedBy   = "Terraform"
      Lab         = "Lab2-IAM-Audit"
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
      Project     = "IAM-Access-Analyzer-Lab"
      Environment = "Dev"
      ManagedBy   = "Terraform"
      Lab         = "Lab2-IAM-Audit"
    }
  }
}

# Additional region providers for multi-region Access Analyzer
provider "aws" {
  alias   = "security_uswest2"
  region  = "us-west-2"
  profile = var.security_account_profile

  default_tags {
    tags = {
      Project     = "IAM-Access-Analyzer-Lab"
      Environment = "Security"
      ManagedBy   = "Terraform"
      Lab         = "Lab2-IAM-Audit"
    }
  }
}

provider "aws" {
  alias   = "dev_uswest2"
  region  = "us-west-2"
  profile = var.dev_account_profile

  default_tags {
    tags = {
      Project     = "IAM-Access-Analyzer-Lab"
      Environment = "Dev"
      ManagedBy   = "Terraform"
      Lab         = "Lab2-IAM-Audit"
    }
  }
}