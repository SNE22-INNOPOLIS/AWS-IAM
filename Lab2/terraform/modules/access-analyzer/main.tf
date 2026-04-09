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

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = var.analyzer_name
  type          = var.analyzer_type

  tags = merge(var.tags, {
    Name = var.analyzer_name
  })
}

# Unused Access Analyzer (IAM Access Analyzer for unused permissions)
resource "aws_accessanalyzer_analyzer" "unused_access" {
  count = var.enable_unused_access_analyzer ? 1 : 0

  analyzer_name = "${var.analyzer_name}-unused-access"
  type          = var.analyzer_type

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age
    }
  }

  tags = merge(var.tags, {
    Name    = "${var.analyzer_name}-unused-access"
    Purpose = "UnusedAccessAnalysis"
  })
}

# Archive rule to auto-archive known findings (optional)
resource "aws_accessanalyzer_archive_rule" "auto_archive_internal" {
  count = var.enable_auto_archive ? 1 : 0

  analyzer_name = aws_accessanalyzer_analyzer.main.analyzer_name
  rule_name     = "auto-archive-internal"

  filter {
    criteria = "isPublic"
    eq       = ["false"]
  }

  filter {
    criteria = "resourceType"
    eq       = ["AWS::IAM::Role"]
  }
}