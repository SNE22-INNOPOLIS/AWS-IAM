output "findings_bucket_name" {
  description = "Name of the S3 bucket that stores NDJSON findings"
  value       = aws_s3_bucket.findings.bucket
}

output "findings_bucket_arn" {
  description = "ARN of the findings S3 bucket"
  value       = aws_s3_bucket.findings.arn
}

output "athena_workgroup_name" {
  description = "Athena workgroup name"
  value       = aws_athena_workgroup.iam_health.name
}

output "glue_database_name" {
  description = "Glue catalog database name used in Athena SQL"
  value       = aws_glue_catalog_database.iam_health.name
}

output "glue_crawler_name" {
  description = "Glue crawler name"
  value       = aws_glue_crawler.iam_findings.name
}
