# =============================================================================
# IAM Access Analyzer Module
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = var.analyzer_name
  type          = var.analyzer_type

  tags = merge(var.tags, {
    Name        = var.analyzer_name
    Environment = var.environment
  })
}

# Archive Rules for common known patterns (reduce noise)
resource "aws_accessanalyzer_archive_rule" "archive_same_account" {
  analyzer_name = aws_accessanalyzer_analyzer.this.analyzer_name
  rule_name     = "archive-same-account-access"

  filter {
    criteria = "isPublic"
    eq       = ["false"]
  }

  filter {
    criteria = "principal.AWS"
    contains = [var.account_id]
  }
}