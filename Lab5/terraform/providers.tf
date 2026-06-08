terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  alias   = "security"
  region  = var.primary_region
  profile = var.security_account_profile

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "security-lab"
      ManagedBy   = "terraform"
      Lab         = "Lab5"
    }
  }
}
