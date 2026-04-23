# =============================================================================
# Outputs
# =============================================================================

# Access Analyzer Outputs
output "access_analyzer_security_primary_arn" {
  description = "ARN of the IAM Access Analyzer in Security account (primary region)"
  value       = module.access_analyzer_security_primary.analyzer_arn
}

output "access_analyzer_security_secondary_arn" {
  description = "ARN of the IAM Access Analyzer in Security account (secondary region)"
  value       = module.access_analyzer_security_secondary.analyzer_arn
}

output "access_analyzer_dev_primary_arn" {
  description = "ARN of the IAM Access Analyzer in Dev account (primary region)"
  value       = module.access_analyzer_dev_primary.analyzer_arn
}

output "access_analyzer_dev_secondary_arn" {
  description = "ARN of the IAM Access Analyzer in Dev account (secondary region)"
  value       = module.access_analyzer_dev_secondary.analyzer_arn
}

# Lambda Function Outputs
output "iam_audit_lambda_security_arn" {
  description = "ARN of the IAM Audit Lambda in Security account"
  value       = module.iam_audit_lambda_security.lambda_arn
}

output "iam_audit_lambda_security_name" {
  description = "Name of the IAM Audit Lambda in Security account"
  value       = module.iam_audit_lambda_security.lambda_function_name
}

output "iam_audit_lambda_dev_arn" {
  description = "ARN of the IAM Audit Lambda in Dev account"
  value       = module.iam_audit_lambda_dev.lambda_arn
}

output "iam_audit_lambda_dev_name" {
  description = "Name of the IAM Audit Lambda in Dev account"
  value       = module.iam_audit_lambda_dev.lambda_function_name
}

# S3 Bucket Outputs
output "reports_bucket_name" {
  description = "Name of the S3 bucket for IAM audit reports"
  value       = module.iam_audit_reports_bucket.bucket_name
}

output "reports_bucket_arn" {
  description = "ARN of the S3 bucket for IAM audit reports"
  value       = module.iam_audit_reports_bucket.bucket_arn
}

# Test Role Outputs
output "test_role_security_arn" {
  description = "ARN of the test IAM role in Security account"
  value       = var.create_test_roles ? aws_iam_role.test_role_security[0].arn : null
}

output "test_role_dev_arn" {
  description = "ARN of the test IAM role in Dev account"
  value       = var.create_test_roles ? aws_iam_role.test_role_dev[0].arn : null
}

# SNS Topic Output
output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = var.enable_sns_notifications ? aws_sns_topic.iam_audit_notifications[0].arn : null
}

# Invocation Commands
output "invoke_lambda_security_command" {
  description = "AWS CLI command to invoke the Security account Lambda"
  value       = "aws lambda invoke --function-name ${module.iam_audit_lambda_security.lambda_function_name} --profile ${var.security_account_profile} --region ${var.primary_region} /tmp/security-audit-output.json && cat /tmp/security-audit-output.json"
}

output "invoke_lambda_dev_command" {
  description = "AWS CLI command to invoke the Dev account Lambda"
  value       = "aws lambda invoke --function-name ${module.iam_audit_lambda_dev.lambda_function_name} --profile ${var.dev_account_profile} --region ${var.primary_region} /tmp/dev-audit-output.json && cat /tmp/dev-audit-output.json"
}

# Report Location
output "reports_s3_path" {
  description = "S3 path where reports are stored"
  value       = "s3://${module.iam_audit_reports_bucket.bucket_name}/iam-audit-reports/"
}