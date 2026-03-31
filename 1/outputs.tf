output "security_account_id" {
  value = aws_organizations_account.security.id
}

output "dev_account_id" {
  value = aws_organizations_account.dev.id
}

output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.org_trail.arn
}