output "security_account_id" {
  value = data.aws_caller_identity.security.account_id
}

output "dev_account_id" {
  value = data.aws_caller_identity.dev.account_id
}

output "cloudtrail_bucket_name" {
  value = var.cloudtrail_bucket_name
}

output "config_bucket_name" {
  value = var.config_bucket_name
}