locals {
  common_tags = {
    Project     = var.project_name
    Environment = "security-lab"
    ManagedBy   = "terraform"
    Lab         = "Lab5"
  }
}

module "data_pipeline" {
  source = "./modules/data-pipeline"

  providers = {
    aws = aws.security
  }

  project_name            = var.project_name
  account_id              = var.security_account_id
  glue_crawler_schedule   = var.glue_crawler_schedule
  findings_retention_days = var.findings_retention_days
  athena_bytes_scanned_cutoff = var.athena_bytes_scanned_cutoff
  tags                    = local.common_tags
}

module "security_hub_export" {
  source = "./modules/security-hub-export"

  providers = {
    aws = aws.security
  }

  project_name              = var.project_name
  account_id                = var.security_account_id
  aws_region                = var.primary_region
  lambda_source_dir         = "${path.root}/../scripts/aggregator"
  findings_bucket_name      = module.data_pipeline.findings_bucket_name
  findings_bucket_arn       = module.data_pipeline.findings_bucket_arn
  analyzer_arn              = var.analyzer_arn
  key_age_threshold_days    = var.key_age_threshold_days
  schedule_expression       = var.lambda_schedule_expression
  lambda_runtime            = var.lambda_runtime
  lambda_timeout            = var.lambda_timeout
  lambda_memory_size        = var.lambda_memory_size
  log_retention_days        = var.log_retention_days
  tags                      = local.common_tags
}

module "quicksight" {
  source = "./modules/quicksight"

  providers = {
    aws = aws.security
  }

  project_name          = var.project_name
  account_id            = var.security_account_id
  aws_region            = var.primary_region
  quicksight_user_arn   = var.quicksight_user_arn
  quicksight_namespace  = var.quicksight_namespace
  glue_database_name    = module.data_pipeline.glue_database_name
  athena_workgroup_name = module.data_pipeline.athena_workgroup_name
  findings_bucket_name  = module.data_pipeline.findings_bucket_name
  findings_bucket_arn   = module.data_pipeline.findings_bucket_arn
  tags                  = local.common_tags
}
