output "lambda_arn" {
  description = "ARN of the credential rotator Lambda function"
  value       = aws_lambda_function.rotator.arn
}

output "lambda_name" {
  description = "Name of the credential rotator Lambda function"
  value       = aws_lambda_function.rotator.function_name
}

output "iam_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda.arn
}

output "iam_role_name" {
  description = "Name of the Lambda execution role"
  value       = aws_iam_role.lambda.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.weekly_rotation.arn
}

output "log_group_name" {
  description = "CloudWatch log group for Lambda execution logs"
  value       = aws_cloudwatch_log_group.lambda.name
}
