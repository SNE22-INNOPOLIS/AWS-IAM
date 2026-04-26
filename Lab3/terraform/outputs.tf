# =============================================================================
# Outputs - Lab 3
# =============================================================================

# Permission Boundary Outputs
output "permission_boundary_security_arn" {
  description = "ARN of permission boundary in Security account"
  value       = module.permission_boundaries_security.boundary_policy_arn
}

output "permission_boundary_dev_arn" {
  description = "ARN of permission boundary in Dev account"
  value       = module.permission_boundaries_dev.boundary_policy_arn
}

# MFA Enforcement Policy Outputs
output "mfa_enforcement_policy_security_arn" {
  description = "ARN of MFA enforcement policy in Security account"
  value       = module.mfa_enforcement_security.mfa_policy_arn
}

output "mfa_enforcement_policy_dev_arn" {
  description = "ARN of MFA enforcement policy in Dev account"
  value       = module.mfa_enforcement_dev.mfa_policy_arn
}

# BreakGlass Role Outputs
output "breakglass_role_security_arn" {
  description = "ARN of BreakGlass role in Security account"
  value       = module.breakglass_security.breakglass_role_arn
}

output "breakglass_role_dev_arn" {
  description = "ARN of BreakGlass role in Dev account"
  value       = module.breakglass_dev.breakglass_role_arn
}

# Lambda Outputs
output "guardrail_enforcement_lambda_arn" {
  description = "ARN of guardrail enforcement Lambda"
  value       = module.guardrail_enforcement_lambda_dev.lambda_arn
}

# SNS Topic
output "guardrail_alerts_topic_arn" {
  description = "ARN of SNS topic for guardrail alerts"
  value       = aws_sns_topic.guardrail_alerts.arn
}

# Test Commands
output "test_permission_boundary_command" {
  description = "Command to test permission boundary (should fail)"
  value       = "aws iam create-user --user-name test-blocked-user --profile dev"
}

output "assume_breakglass_role_command" {
  description = "Command to assume BreakGlass role"
  value       = "aws sts assume-role --role-arn ${module.breakglass_dev.breakglass_role_arn} --role-session-name breakglass-session --profile security"
}