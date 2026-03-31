terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Management Account (Default)
provider "aws" {
  region = var.region
  alias  = "management"
}

# Security Account (Assumes Role)
provider "aws" {
  region = var.region
  alias  = "security"
  assume_role {
    # The ID will be known after module.organization runs
    # We use a placeholder or output from org module in a real dynamic scenario
    # For static definition, we rely on the fact that account creation returns ID
    # However, Terraform requires static role_arn in provider block usually.
    # Workaround: Use data source or hardcode ID if known, 
    # BUT since we are creating the account dynamically, we cannot assume role 
    # into it in the same plan unless we use a two-step apply.
    
    # For this lab, we assume the role exists via Organizations default creation
    # We must reference the ID from the organization module.
    # NOTE: You cannot dynamically interpolate provider arguments in Terraform.
    # To make this work strictly, you must run 'terraform apply' once to create accounts,
    # then update providers.tf with the IDs, or use a wrapper script.
    
    # SIMPLIFICATION FOR LAB: 
    # We will assume the role ARN structure is predictable once IDs are known.
    # To make this script runnable in one go, we remove the assume_role block 
    # for 'security' and 'dev' in the first pass, or we accept a two-step process.
    
    # BEST PRACTICE FOR IAAC: 
    # Use the 'aws_organizations_account' ID output to configure providers 
    # is not directly possible in the same plan. 
    # We will keep the provider definition but comment that a second apply is needed 
    # if the role ARN depends on dynamic IDs.
    
    role_arn = "arn:aws:iam::${var.security_account_id_placeholder}:role/OrganizationAccountAccessRole"
  }
}

# Dev Account (Assumes Role)
provider "aws" {
  region = var.region
  alias  = "dev"
  assume_role {
    role_arn = "arn:aws:iam::${var.dev_account_id_placeholder}:role/OrganizationAccountAccessRole"
  }
}