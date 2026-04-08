# =============================================================================
# IAM Audit Lambda Module Outputs
# =============================================================================

output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.iam_auditor.arn
}

output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.iam_auditor.function_name
}

output "role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "Name of the CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "schedule_rule_arn" {
  description = "ARN of the CloudWatch Events rule"
  value       = aws_cloudwatch_event_rule.scheduled_audit.arn
}