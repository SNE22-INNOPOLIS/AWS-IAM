# =============================================================================
# Main Configuration - Multi-Account Security Lab
# =============================================================================

locals {
  common_tags = merge(var.tags, {
    SecurityLab = "true"
    AuditScope  = "IAM-Permissions"
  })

  # S3 bucket name with account ID for uniqueness
  report_bucket_name = var.s3_report_bucket_name != "" ? var.s3_report_bucket_name : "iam-audit-reports-${var.security_account_id}-${var.environment}"
}

# Get current AWS account info
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# =============================================================================
# Access Analyzer Module - Primary Account
# =============================================================================

module "access_analyzer_primary" {
  source = "./modules/access-analyzer"

  analyzer_name                = "security-lab-analyzer-${var.environment}"
  analyzer_type                = var.enable_organization_analyzer ? "ORGANIZATION" : "ACCOUNT"
  enable_unused_access_analyzer = true
  unused_access_age            = var.unused_threshold_days
  environment                  = var.environment
  tags                         = local.common_tags
}

# =============================================================================
# Access Analyzer for Additional Regions (Primary Account)
# =============================================================================

module "access_analyzer_additional_regions" {
  source   = "./modules/access-analyzer"
  for_each = toset(var.additional_regions)

  providers = {
    aws = aws
  }

  analyzer_name                = "security-lab-analyzer-${var.environment}-${each.key}"
  analyzer_type                = "ACCOUNT"
  enable_unused_access_analyzer = true
  unused_access_age            = var.unused_threshold_days
  environment                  = var.environment
  tags                         = local.common_tags
}

# =============================================================================
# S3 Bucket for Audit Reports
# =============================================================================

resource "aws_s3_bucket" "audit_reports" {
  bucket = local.report_bucket_name

  tags = merge(local.common_tags, {
    Name = "IAM Audit Reports"
  })
}

resource "aws_s3_bucket_versioning" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# =============================================================================
# SNS Topic for Notifications
# =============================================================================

resource "aws_sns_topic" "audit_notifications" {
  name = "iam-audit-notifications-${var.environment}"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count = var.notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.audit_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sns_topic_policy" "audit_notifications" {
  arn = aws_sns_topic.audit_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.audit_notifications.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"
          }
        }
      }
    ]
  })
}

# =============================================================================
# IAM Audit Lambda Module
# =============================================================================

module "iam_audit_lambda" {
  source = "./modules/iam-audit-lambda"

  function_name           = "iam-permission-auditor-${var.environment}"
  environment             = var.environment
  unused_threshold_days   = var.unused_threshold_days
  s3_bucket_name          = aws_s3_bucket.audit_reports.id
  sns_topic_arn           = aws_sns_topic.audit_notifications.arn
  schedule_expression     = var.lambda_schedule_expression
  member_account_ids      = var.member_account_ids
  cross_account_role_name = var.cross_account_role_name
  tags                    = local.common_tags

  depends_on = [
    aws_s3_bucket.audit_reports
  ]
}

# =============================================================================
# Test IAM Roles for Demonstration
# =============================================================================

resource "aws_iam_role" "test_roles" {
  for_each = { for role in var.test_roles_to_create : role.name => role }

  name        = each.value.name
  description = each.value.description

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(local.common_tags, {
    TestRole = "true"
    Purpose  = "IAM-Audit-Demo"
  })
}

# Attach managed policies to test roles for demonstration
resource "aws_iam_role_policy_attachment" "test_role_policies" {
  for_each = { for role in var.test_roles_to_create : role.name => role }

  role       = aws_iam_role.test_roles[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Custom policy for test roles with broader permissions (to demonstrate unused services)
resource "aws_iam_role_policy" "test_role_custom" {
  for_each = { for role in var.test_roles_to_create : role.name => role }

  name = "${each.value.name}-custom-policy"
  role = aws_iam_role.test_roles[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificServices"
        Effect = "Allow"
        Action = [for svc in each.value.services : "${svc}:*"]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Cross-Account Role (to be deployed in member accounts)
# =============================================================================

resource "aws_iam_role" "cross_account_audit_role" {
  count = length(var.member_account_ids) > 0 ? 1 : 0

  name        = "IAMAuditCrossAccountRole"
  description = "Role assumed by Security Lab Lambda for IAM auditing"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "security-lab-audit-${var.environment}"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cross_account_audit_policy" {
  count = length(var.member_account_ids) > 0 ? 1 : 0

  name = "IAMAuditPolicy"
  role = aws_iam_role.cross_account_audit_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadAccess"
        Effect = "Allow"
        Action = [
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "iam:ListRoles",
          "iam:ListUsers",
          "iam:ListPolicies",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetRole",
          "iam:GetUser",
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "*"
      },
      {
        Sid    = "AccessAnalyzerRead"
        Effect = "Allow"
        Action = [
          "access-analyzer:List*",
          "access-analyzer:Get*"
        ]
        Resource = "*"
      }
    ]
  })
}