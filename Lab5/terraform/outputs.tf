output "account_id" {
  description = "AWS account ID"
  value       = var.security_account_id
}

output "findings_bucket_name" {
  description = "S3 bucket that stores NDJSON findings partitions"
  value       = module.data_pipeline.findings_bucket_name
}

output "findings_bucket_arn" {
  description = "ARN of the findings S3 bucket"
  value       = module.data_pipeline.findings_bucket_arn
}

output "athena_workgroup_name" {
  description = "Athena workgroup to use when running the SQL queries in scripts/sql/"
  value       = module.data_pipeline.athena_workgroup_name
}

output "glue_database_name" {
  description = "Glue catalog database name; Athena table references use this prefix"
  value       = module.data_pipeline.glue_database_name
}

output "glue_crawler_name" {
  description = "Name of the Glue crawler — trigger manually after the first Lambda invocation"
  value       = module.data_pipeline.glue_crawler_name
}

output "lambda_function_name" {
  description = "IAM findings aggregator Lambda function name"
  value       = module.security_hub_export.lambda_function_name
}

output "lambda_function_arn" {
  description = "IAM findings aggregator Lambda function ARN"
  value       = module.security_hub_export.lambda_function_arn
}

output "quicksight_data_source_arn" {
  description = "ARN of the QuickSight Athena data source (empty when enable_quicksight = false)"
  value       = var.enable_quicksight ? module.quicksight[0].data_source_arn : ""
}

output "quicksight_unused_permissions_dataset_arn" {
  description = "ARN of the QuickSight dataset for unused role permissions (empty when enable_quicksight = false)"
  value       = var.enable_quicksight ? module.quicksight[0].unused_permissions_dataset_arn : ""
}

output "quicksight_stale_keys_dataset_arn" {
  description = "ARN of the QuickSight dataset for stale access keys (empty when enable_quicksight = false)"
  value       = var.enable_quicksight ? module.quicksight[0].stale_keys_dataset_arn : ""
}

output "quicksight_scp_violations_dataset_arn" {
  description = "ARN of the QuickSight dataset for SCP violations (empty when enable_quicksight = false)"
  value       = var.enable_quicksight ? module.quicksight[0].scp_violations_dataset_arn : ""
}

output "quicksight_user_arn" {
  description = "QuickSight user ARN — passed to the deploy_dashboard.sh script"
  value       = var.quicksight_user_arn
}

output "quicksight_dashboard_url" {
  description = "Console URL for the dashboard (available after running deploy_dashboard.sh)"
  value       = "https://${var.primary_region}.quicksight.aws.amazon.com/sn/dashboards/iam-health-dashboard"
}
