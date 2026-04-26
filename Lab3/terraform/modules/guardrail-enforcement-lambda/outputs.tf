output "lambda_arn" {
  description = "ARN of the enforcement Lambda"
  value       = aws_lambda_function.enforcement.arn
}

output "lambda_function_name" {
  description = "Name of the enforcement Lambda"
  value       = aws_lambda_function.enforcement.function_name
}

output "lambda_role_arn" {
  description = "ARN of Lambda execution role"
  value       = aws_iam_role.lambda_role.arn
}