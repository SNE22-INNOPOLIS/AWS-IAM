output "boundary_policy_arn" {
  description = "ARN of the permission boundary policy"
  value       = aws_iam_policy.permission_boundary.arn
}

output "boundary_policy_name" {
  description = "Name of the permission boundary policy"
  value       = aws_iam_policy.permission_boundary.name
}

output "enforced_role_example_arn" {
  description = "ARN of example role with boundary attached"
  value       = aws_iam_role.enforced_role_example.arn
}