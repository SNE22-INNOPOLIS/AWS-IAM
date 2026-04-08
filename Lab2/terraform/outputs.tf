# =============================================================================
# Outputs for Multi-Account Security Lab
# =============================================================================

output "access_analyzer_arn" {
  description = "ARN of the primary IAM Access Analyzer"
  value       = module.access_analyzer_primary.analyzer_arn
}

output "access_analyzer_id" {
  description = "ID of the primary IAM Access Analyzer"
  value       = module.access_analyzer_primary.analyzer_id
}

output "lambda_function_arn" {
  description = "ARN of the IAM Audit Lambda function"
  value       = module.iam_audit_lambda.function_arn
}

output "lambda_function_name" {
  description = "Name of the IAM Audit Lambda function"
  value       = module.iam_audit_lambda.function_name
}

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

output "test_role_arns" {
  description = "ARNs of the test IAM roles created for demonstration"
  value       = { for k, v in aws_iam_role.test_roles : k => v.arn }
}

output "invoke_lambda_command" {
  description = "AWS CLI command to manually invoke the Lambda function"
  value       = <<-EOT
    aws lambda invoke \
      --function-name ${module.iam_audit_lambda.function_name} \
      --payload '{"report_type": "full", "threshold_days": ${var.unused_threshold_days}}' \
      --cli-binary-format raw-in-base64-out \
      response.json
  EOT
}

output "view_reports_command" {
  description = "AWS CLI command to list audit reports in S3"
  value       = "aws s3 ls s3://${aws_s3_bucket.audit_reports.id}/reports/ --recursive"
}

output "cross_account_role_arn" {
  description = "ARN of the cross-account audit role (if created)"
  value       = length(aws_iam_role.cross_account_audit_role) > 0 ? aws_iam_role.cross_account_audit_role[0].arn : null
}