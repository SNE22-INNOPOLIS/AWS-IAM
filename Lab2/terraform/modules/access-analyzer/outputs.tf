# =============================================================================
# Access Analyzer Module Outputs
# =============================================================================

output "analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.main.arn
}

output "analyzer_id" {
  description = "ID of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.main.id
}

output "analyzer_name" {
  description = "Name of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.main.analyzer_name
}

output "unused_access_analyzer_arn" {
  description = "ARN of the Unused Access Analyzer"
  value       = var.enable_unused_access_analyzer ? aws_accessanalyzer_analyzer.unused_access[0].arn : null
}