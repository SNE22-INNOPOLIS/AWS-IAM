output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail.bucket
}

output "config_bucket_name" {
  value = aws_s3_bucket.config.bucket
}