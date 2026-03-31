# 1. Organization Module (Uses Management Account)
module "organization" {
  source = "./modules/organization"

  security_account_email = var.security_account_email
  dev_account_email      = var.dev_account_email

  providers = {
    aws = aws.management
  }
}

# 2. Logging Module (Uses Security Account)
# Depends on Org so the account exists to assume role into
module "logging" {
  source = "./modules/logging"

  environment = var.environment

  providers = {
    aws = aws.security
  }

  depends_on = [module.organization]
}

# 3. Compliance Module (Uses Management Account)
# Depends on Logging so the bucket exists for CloudTrail
module "compliance" {
  source = "./modules/compliance"

  environment     = var.environment
  log_bucket_name = module.logging.bucket_name

  providers = {
    aws = aws.management
  }

  depends_on = [module.logging]
}