# =============================================================================
# IAM Audit Lambda Module
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

data "aws_region" "current" {}

# Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "${var.function_name}-role"

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

  tags = merge(var.tags, {
    Name = "${var.function_name}-role"
  })
}

# IAM policy for Lambda
resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.function_name}-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadAccess"
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:ListUsers",
          "iam:GetRole",
          "iam:GetUser",
          "iam:ListRolePolicies",
          "iam:ListUserPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetRolePolicy",
          "iam:GetUserPolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails"
        ]
        Resource = "*"
      },
      {
        Sid    = "AccessAnalyzerAccess"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3WriteAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${var.reports_bucket_arn}/iam-audit-reports/${var.account_name}/*"
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${var.account_id}:log-group:/aws/lambda/${var.function_name}:*"
      },
      {
        Sid    = "SNSPublishAccess"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Purpose" = "IAM Audit Notifications"
          }
        }
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 30

  tags = merge(var.tags, {
    Name = "${var.function_name}-logs"
  })
}

# Package Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/iam-audit"
  output_path = "${path.module}/lambda_function.zip"
  excludes    = ["local_runner.py", "test_lambda.py", "__pycache__", "*.pyc", "requirements.txt"]
}

# Lambda function
resource "aws_lambda_function" "iam_audit" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = var.function_name
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 900  # 15 minutes max
  memory_size      = 512

  environment {
    variables = {
      REPORTS_BUCKET       = var.reports_bucket_name
      ACCOUNT_NAME         = var.account_name
      ACCOUNT_ID           = var.account_id
      THRESHOLD_DAYS       = tostring(var.unused_threshold_days)
      ENVIRONMENT          = var.environment
      SNS_TOPIC_ARN        = var.sns_topic_arn
      ENABLE_NOTIFICATIONS = tostring(var.enable_sns_notifications)
    }
  }

  tags = merge(var.tags, {
    Name = var.function_name
  })

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_policy
  ]
}

# EventBridge rule for scheduled execution
resource "aws_cloudwatch_event_rule" "scheduled_audit" {
  count = var.enable_scheduled_execution ? 1 : 0

  name                = "${var.function_name}-schedule"
  description         = "Scheduled execution of IAM audit Lambda"
  schedule_expression = var.schedule_expression

  tags = merge(var.tags, {
    Name = "${var.function_name}-schedule"
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  count = var.enable_scheduled_execution ? 1 : 0

  rule      = aws_cloudwatch_event_rule.scheduled_audit[0].name
  target_id = "iam-audit-lambda"
  arn       = aws_lambda_function.iam_audit.arn

  input = jsonencode({
    "source": "scheduled-event",
    "detail-type": "Scheduled IAM Audit"
  })
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.enable_scheduled_execution ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_audit.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_audit[0].arn
}