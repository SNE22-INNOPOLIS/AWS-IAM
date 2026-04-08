# =============================================================================
# IAM Audit Lambda Module
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# =============================================================================
# Lambda IAM Role
# =============================================================================

resource "aws_iam_role" "lambda_role" {
  name = "${var.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for Lambda
resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.function_name}-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid    = "IAMReadAccess"
        Effect = "Allow"
        Action = [
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetailsWithEntities",
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
          "iam:GetPolicyVersion",
          "iam:GetRolePolicy",
          "iam:GetUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "AccessAnalyzerRead"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding",
          "access-analyzer:ListAccessPreviews",
          "access-analyzer:GetAccessPreview"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3WriteReports"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.s3_bucket_name}",
          "arn:${data.aws_partition.current.partition}:s3:::${var.s3_bucket_name}/*"
        ]
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn
      },
      {
        Sid    = "CrossAccountAssume"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = [
          for account_id in var.member_account_ids :
          "arn:${data.aws_partition.current.partition}:iam::${account_id}:role/${var.cross_account_role_name}"
        ]
      }
    ]
  })
}

# =============================================================================
# Lambda Function Package
# =============================================================================

data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/iam-audit"
  output_path = "${path.module}/lambda_package.zip"

  excludes = [
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    "tests",
    "README.md",
    "iam_audit_standalone.py"
  ]
}

# =============================================================================
# Lambda Function
# =============================================================================

resource "aws_lambda_function" "iam_auditor" {
  function_name = var.function_name
  description   = "Audits IAM permissions and identifies unused services"

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  handler = "lambda_function.lambda_handler"
  runtime = "python3.11"
  timeout = 900  # 15 minutes for large accounts
  memory_size = 512

  role = aws_iam_role.lambda_role.arn

  environment {
    variables = {
      UNUSED_THRESHOLD_DAYS   = tostring(var.unused_threshold_days)
      S3_BUCKET_NAME          = var.s3_bucket_name
      SNS_TOPIC_ARN           = var.sns_topic_arn
      ENVIRONMENT             = var.environment
      MEMBER_ACCOUNT_IDS      = jsonencode(var.member_account_ids)
      CROSS_ACCOUNT_ROLE_NAME = var.cross_account_role_name
      LOG_LEVEL               = var.log_level
    }
  }

  tags = var.tags
}

# CloudWatch Log Group with retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.iam_auditor.function_name}"
  retention_in_days = 30

  tags = var.tags
}

# =============================================================================
# CloudWatch Event Rule for Scheduled Execution
# =============================================================================

resource "aws_cloudwatch_event_rule" "scheduled_audit" {
  name                = "${var.function_name}-schedule"
  description         = "Triggers IAM audit Lambda on schedule"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_audit.name
  target_id = "IAMAuditLambda"
  arn       = aws_lambda_function.iam_auditor.arn

  input = jsonencode({
    report_type    = "full"
    threshold_days = var.unused_threshold_days
    send_notification = true
  })
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_audit.arn
}