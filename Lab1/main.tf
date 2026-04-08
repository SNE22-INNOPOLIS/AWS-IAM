data "aws_caller_identity" "security" {
  provider = aws.security
}

data "aws_caller_identity" "dev" {
  provider = aws.dev
}

module "central_logging" {
  source = "./modules/central_logging"

  providers = {
    aws = aws.security
  }

  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  config_bucket_name     = var.config_bucket_name
  security_account_id    = data.aws_caller_identity.security.account_id
  dev_account_id         = data.aws_caller_identity.dev.account_id
}

module "cloudtrail_security" {
  source = "./modules/account_cloudtrail"

  providers = {
    aws = aws.security
  }

  trail_name          = var.trail_name_security
  s3_bucket_name      = var.cloudtrail_bucket_name
  account_id          = data.aws_caller_identity.security.account_id
  enable_multi_region = true
  depends_on          = [module.central_logging]
}

module "cloudtrail_dev" {
  source = "./modules/account_cloudtrail"

  providers = {
    aws = aws.dev
  }

  trail_name          = var.trail_name_dev
  s3_bucket_name      = var.cloudtrail_bucket_name
  account_id          = data.aws_caller_identity.dev.account_id
  enable_multi_region = true
  depends_on          = [module.central_logging]
}

module "config_security" {
  source = "./modules/account_config"

  providers = {
    aws = aws.security
  }

  recorder_name        = var.config_recorder_name_security
  delivery_bucket_name = var.config_bucket_name

  depends_on = [module.central_logging]
}

module "config_dev" {
  source = "./modules/account_config"

  providers = {
    aws = aws.dev
  }

  recorder_name        = var.config_recorder_name_dev
  delivery_bucket_name = var.config_bucket_name

  depends_on = [module.central_logging]
}

module "pack_security" {
  source = "./modules/conformance_pack"

  providers = {
    aws = aws.security
  }

  name          = "iam-best-practices"
  template_body = file("${path.module}/conformance-packs/iam-conformance-pack.yaml")
}

module "pack_dev" {
  source = "./modules/conformance_pack"

  providers = {
    aws = aws.dev
  }

  name          = "iam-best-practices"
  template_body = file("${path.module}/conformance-packs/iam-conformance-pack.yaml")
}