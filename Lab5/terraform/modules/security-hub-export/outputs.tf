output "lambda_function_name" {
  description = "Name of the IAM findings aggregator Lambda"
  value       = aws_lambda_function.aggregator.function_name
}

output "lambda_function_arn" {
  description = "ARN of the IAM findings aggregator Lambda"
  value       = aws_lambda_function.aggregator.arn
}

output "lambda_role_arn" {
  description = "IAM role ARN used by the Lambda"
  value       = aws_iam_role.aggregator.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN for the Lambda schedule"
  value       = aws_cloudwatch_event_rule.aggregator_schedule.arn
}
