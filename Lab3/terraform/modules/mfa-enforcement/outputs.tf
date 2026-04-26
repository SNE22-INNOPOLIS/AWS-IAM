output "mfa_policy_arn" {
  description = "ARN of MFA enforcement policy"
  value       = aws_iam_policy.require_mfa_destructive.arn
}

output "mfa_group_name" {
  description = "Name of MFA enforced group"
  value       = aws_iam_group.mfa_enforced.name
}

output "self_manage_mfa_policy_arn" {
  description = "ARN of self-manage MFA policy"
  value       = aws_iam_policy.self_manage_mfa.arn
}