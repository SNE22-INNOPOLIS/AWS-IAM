terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  alias   = "security"
  region  = var.aws_region
  profile = var.security_profile
}

provider "aws" {
  alias   = "dev"
  region  = var.aws_region
  profile = var.dev_profile
}