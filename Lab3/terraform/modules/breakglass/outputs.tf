output "breakglass_role_arn" {
  description = "ARN of the BreakGlass role"
  value       = aws_iam_role.breakglass.arn
}

output "breakglass_role_name" {
  description = "Name of the BreakGlass role"
  value       = aws_iam_role.breakglass.name
}