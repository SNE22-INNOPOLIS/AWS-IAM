output "lambda_function_name" {
  description = "Name of the credential rotator Lambda function"
  value       = module.key_rotator.lambda_name
}

output "lambda_function_arn" {
  description = "ARN of the credential rotator Lambda function"
  value       = module.key_rotator.lambda_arn
}

output "lambda_iam_role_arn" {
  description = "ARN of the Lambda execution role (least-privilege IAM policy)"
  value       = module.key_rotator.iam_role_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS notification topic"
  value       = module.notifications.topic_arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge weekly rotation rule"
  value       = module.key_rotator.eventbridge_rule_arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for Lambda execution logs"
  value       = module.key_rotator.log_group_name
}
