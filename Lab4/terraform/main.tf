locals {
  common_tags = {
    Project     = var.project_name
    Environment = "security-lab"
    ManagedBy   = "terraform"
    Lab         = "Lab4"
  }
}

module "notifications" {
  source = "./modules/notifications"

  providers = {
    aws = aws.security
  }

  project_name       = var.project_name
  environment        = "security-lab"
  notification_email = var.notification_email
  kms_key_alias      = var.kms_key_alias
  tags               = local.common_tags
}

module "key_rotator" {
  source = "./modules/key-rotator"

  providers = {
    aws = aws.security
  }

  project_name      = var.project_name
  environment       = "security-lab"
  aws_region        = var.primary_region
  account_id        = var.security_account_id
  lambda_source_dir = "${path.root}/../../lambda/credential-rotator"

  rotation_age_days   = var.rotation_age_days
  schedule_expression = var.lambda_schedule_expression
  sns_topic_arn       = module.notifications.topic_arn
  secret_prefix       = var.secret_prefix
  protected_users     = var.protected_users
  dry_run             = var.enable_dry_run
  lambda_runtime      = var.lambda_runtime
  lambda_timeout      = var.lambda_timeout
  lambda_memory_size  = var.lambda_memory_size
  log_retention_days  = var.log_retention_days

  tags = local.common_tags
}
