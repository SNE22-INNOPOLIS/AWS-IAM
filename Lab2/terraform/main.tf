# =============================================================================
# Main Terraform Configuration
# IAM Access Analyzer & Unused Permission Audit
# =============================================================================

# Get current account information
data "aws_caller_identity" "security" {
  provider = aws.security
}

data "aws_caller_identity" "dev" {
  provider = aws.dev
}

data "aws_region" "current" {
  provider = aws.security
}

# =============================================================================
# S3 Bucket for IAM Audit Reports (Security Account)
# =============================================================================

module "iam_audit_reports_bucket" {
  source = "./modules/s3-reports-bucket"

  providers = {
    aws = aws.security
  }

  bucket_name         = "${var.project_name}-reports-${var.security_account_id}"
  security_account_id = var.security_account_id
  dev_account_id      = var.dev_account_id
  environment         = var.environment

  tags = {
    Purpose = "IAM Audit Reports Storage"
  }
}

# =============================================================================
# IAM Access Analyzer - Security Account (Primary Region)
# =============================================================================

module "access_analyzer_security_primary" {
  source = "./modules/iam-access-analyzer"

  providers = {
    aws = aws.security
  }

  analyzer_name = "${var.project_name}-analyzer-security-${var.primary_region}"
  analyzer_type = "ACCOUNT"
  account_id    = var.security_account_id
  environment   = var.environment

  tags = {
    Account = "Security"
    Region  = var.primary_region
  }
}

# IAM Access Analyzer - Security Account (Secondary Region)
module "access_analyzer_security_secondary" {
  source = "./modules/iam-access-analyzer"

  providers = {
    aws = aws.security_uswest2
  }

  analyzer_name = "${var.project_name}-analyzer-security-us-west-2"
  analyzer_type = "ACCOUNT"
  account_id    = var.security_account_id
  environment   = var.environment

  tags = {
    Account = "Security"
    Region  = "us-west-2"
  }
}

# =============================================================================
# IAM Access Analyzer - Dev Account (Primary Region)
# =============================================================================

module "access_analyzer_dev_primary" {
  source = "./modules/iam-access-analyzer"

  providers = {
    aws = aws.dev
  }

  analyzer_name = "${var.project_name}-analyzer-dev-${var.primary_region}"
  analyzer_type = "ACCOUNT"
  account_id    = var.dev_account_id
  environment   = var.environment

  tags = {
    Account = "Dev"
    Region  = var.primary_region
  }
}

# IAM Access Analyzer - Dev Account (Secondary Region)
module "access_analyzer_dev_secondary" {
  source = "./modules/iam-access-analyzer"

  providers = {
    aws = aws.dev_uswest2
  }

  analyzer_name = "${var.project_name}-analyzer-dev-us-west-2"
  analyzer_type = "ACCOUNT"
  account_id    = var.dev_account_id
  environment   = var.environment

  tags = {
    Account = "Dev"
    Region  = "us-west-2"
  }
}

# =============================================================================
# SNS Topic for Notifications (Security Account) - Create before Lambda
# =============================================================================

resource "aws_sns_topic" "iam_audit_notifications" {
  count    = var.enable_sns_notifications ? 1 : 0
  provider = aws.security

  name = "${var.project_name}-notifications"

  tags = {
    Purpose = "IAM Audit Notifications"
  }
}

resource "aws_sns_topic_subscription" "email_subscription" {
  count    = var.enable_sns_notifications && var.notification_email != "" ? 1 : 0
  provider = aws.security

  topic_arn = aws_sns_topic.iam_audit_notifications[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# SNS Topic Policy to allow cross-account publishing
resource "aws_sns_topic_policy" "iam_audit_notifications_policy" {
  count    = var.enable_sns_notifications ? 1 : 0
  provider = aws.security

  arn = aws_sns_topic.iam_audit_notifications[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCrossAccountPublish"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${var.security_account_id}:root",
            "arn:aws:iam::${var.dev_account_id}:root"
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.iam_audit_notifications[0].arn
      }
    ]
  })
}

# =============================================================================
# IAM Audit Lambda - Security Account
# =============================================================================

module "iam_audit_lambda_security" {
  source = "./modules/iam-audit-lambda"

  providers = {
    aws = aws.security
  }

  function_name              = "${var.project_name}-lambda-security"
  account_id                 = var.security_account_id
  account_name               = "security"
  reports_bucket_name        = module.iam_audit_reports_bucket.bucket_name
  reports_bucket_arn         = module.iam_audit_reports_bucket.bucket_arn
  unused_threshold_days      = var.unused_permission_threshold_days
  enable_scheduled_execution = var.enable_scheduled_execution
  schedule_expression        = var.lambda_schedule_expression
  enable_sns_notifications   = var.enable_sns_notifications
  notification_email         = var.notification_email
  sns_topic_arn              = var.enable_sns_notifications ? aws_sns_topic.iam_audit_notifications[0].arn : ""
  environment                = var.environment

  tags = {
    Account = "Security"
  }

  depends_on = [module.iam_audit_reports_bucket]
}

# =============================================================================
# IAM Audit Lambda - Dev Account
# =============================================================================

module "iam_audit_lambda_dev" {
  source = "./modules/iam-audit-lambda"

  providers = {
    aws = aws.dev
  }

  function_name              = "${var.project_name}-lambda-dev"
  account_id                 = var.dev_account_id
  account_name               = "dev"
  reports_bucket_name        = module.iam_audit_reports_bucket.bucket_name
  reports_bucket_arn         = module.iam_audit_reports_bucket.bucket_arn
  unused_threshold_days      = var.unused_permission_threshold_days
  enable_scheduled_execution = var.enable_scheduled_execution
  schedule_expression        = var.lambda_schedule_expression
  enable_sns_notifications   = var.enable_sns_notifications
  notification_email         = var.notification_email
  sns_topic_arn              = var.enable_sns_notifications ? aws_sns_topic.iam_audit_notifications[0].arn : ""
  environment                = var.environment
  cross_account_bucket       = true

  tags = {
    Account = "Dev"
  }

  depends_on = [module.iam_audit_reports_bucket]
}

# =============================================================================
# Test IAM Roles (for acceptance criteria validation)
# =============================================================================

# Test Role in Security Account
resource "aws_iam_role" "test_role_security" {
  count    = var.create_test_roles ? 1 : 0
  provider = aws.security

  name = "iam-audit-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose  = "IAM Audit Test Role"
    TestRole = "true"
  }
}

resource "aws_iam_role_policy" "test_role_policy_security" {
  count    = var.create_test_roles ? 1 : 0
  provider = aws.security

  name = "test-policy-with-unused-permissions"
  role = aws_iam_role.test_role_security[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "UnusedS3Permissions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Sid    = "UnusedEC2Permissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:StartInstances",
          "ec2:StopInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "UnusedDynamoDBPermissions"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query"
        ]
        Resource = "*"
      },
      {
        Sid    = "UnusedSQSPermissions"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage"
        ]
        Resource = "*"
      }
    ]
  })
}

# Test Role in Dev Account
resource "aws_iam_role" "test_role_dev" {
  count    = var.create_test_roles ? 1 : 0
  provider = aws.dev

  name = "iam-audit-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose  = "IAM Audit Test Role"
    TestRole = "true"
  }
}

resource "aws_iam_role_policy" "test_role_policy_dev" {
  count    = var.create_test_roles ? 1 : 0
  provider = aws.dev

  name = "test-policy-with-unused-permissions"
  role = aws_iam_role.test_role_dev[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "UnusedLambdaPermissions"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "*"
      },
      {
        Sid    = "UnusedSNSPermissions"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:Subscribe",
          "sns:ListTopics"
        ]
        Resource = "*"
      },
      {
        Sid    = "UnusedCloudWatchPermissions"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}