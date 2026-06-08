output "data_source_arn" {
  description = "ARN of the QuickSight Athena data source"
  value       = aws_quicksight_data_source.athena.arn
}

output "unused_permissions_dataset_arn" {
  description = "ARN of the unused permissions daily dataset — used in deploy_dashboard.sh"
  value       = aws_quicksight_data_set.unused_permissions.arn
}

output "stale_keys_dataset_arn" {
  description = "ARN of the stale access keys daily dataset — used in deploy_dashboard.sh"
  value       = aws_quicksight_data_set.stale_keys.arn
}

output "scp_violations_dataset_arn" {
  description = "ARN of the SCP violations daily dataset — used in deploy_dashboard.sh"
  value       = aws_quicksight_data_set.scp_violations.arn
}

output "quicksight_role_arn" {
  description = "ARN of the IAM role granted to QuickSight for Athena access"
  value       = aws_iam_role.quicksight_athena.arn
}
