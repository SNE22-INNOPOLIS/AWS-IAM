output "config_rule_arns" {
  description = "ARNs of all Config rules"
  value = [
    aws_config_config_rule.iam_role_permission_boundary.arn,
    aws_config_config_rule.iam_user_mfa_enabled.arn,
    aws_config_config_rule.root_mfa_enabled.arn,
    aws_config_config_rule.iam_user_no_policies.arn,
    aws_config_config_rule.access_keys_rotated.arn,
    aws_config_config_rule.iam_password_policy.arn
  ]
}

output "lambda_function_name" {
  description = "Guardrail enforcement Lambda name"
  value       = aws_lambda_function.enforcement.function_name
}

output "lambda_arn" {
  description = "ARN of the guardrail enforcement Lambda"
  value       = aws_lambda_function.enforcement.arn
}
