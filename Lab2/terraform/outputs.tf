# =============================================================================
# Outputs for Multi-Account Security Lab
# =============================================================================

# =============================================================================
# Account Information
# =============================================================================


output "security_account_id" {
  description = "Security Account ID"
  value       = data.aws_caller_identity.security.account_id
}

output "dev_account_id" {
  description = "Workloads Account ID"
  value       = data.aws_caller_identity.dev.account_id
}

# =============================================================================
# Access Analyzer
# =============================================================================

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = module.access_analyzer.analyzer_arn
}

output "access_analyzer_id" {
  description = "ID of the IAM Access Analyzer"
  value       = module.access_analyzer.analyzer_id
}

# =============================================================================
# Lambda Function
# =============================================================================

output "lambda_function_arn" {
  description = "ARN of the IAM Audit Lambda function"
  value       = module.iam_audit_lambda.function_arn
}

output "lambda_function_name" {
  description = "Name of the IAM Audit Lambda function"
  value       = module.iam_audit_lambda.function_name
}

# =============================================================================
# S3 and SNS
# =============================================================================

output "s3_bucket_name" {
  description = "Name of the S3 bucket for audit reports"
  value       = aws_s3_bucket.audit_reports.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for audit reports"
  value       = aws_s3_bucket.audit_reports.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = aws_sns_topic.audit_notifications.arn
}

# =============================================================================
# Test Roles
# =============================================================================

output "security_account_test_roles" {
  description = "ARNs of test IAM roles in Security Account"
  value       = { for k, v in aws_iam_role.test_roles : k => v.arn }
}

output "workloads_account_test_roles" {
  description = "ARNs of test IAM roles in Workloads Account"
  value       = { for k, v in aws_iam_role.workloads_test_roles : k => v.arn }
}

# =============================================================================
# Useful Commands
# =============================================================================

output "invoke_lambda_command" {
  description = "AWS CLI command to manually invoke the Lambda function"
  value       = <<-EOT
    aws lambda invoke \
      --function-name ${module.iam_audit_lambda.function_name} \
      --payload '{"report_type": "full", "threshold_days": ${var.unused_threshold_days}}' \
      --cli-binary-format raw-in-base64-out \
      response.json && cat response.json | jq .
  EOT
}

output "view_reports_command" {
  description = "AWS CLI command to list audit reports in S3"
  value       = "aws s3 ls s3://${aws_s3_bucket.audit_reports.id}/reports/ --recursive"
}

output "audit_specific_role_command" {
  description = "AWS CLI command to audit a specific role"
  value       = <<-EOT
    aws lambda invoke \
      --function-name ${module.iam_audit_lambda.function_name} \
      --payload '{"report_type": "specific", "entity_arn": "arn:aws:iam::${var.security_account_id}:role/TestRole-EC2Admin"}' \
      --cli-binary-format raw-in-base64-out \
      response.json && cat response.json | jq .
  EOT
}