terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    archive = {
      source = "hashicorp/archive"
    }
  }
}

# =============================================================================
# security-hub-export module
#
# Creates:
#   - IAM role + policies for the aggregator Lambda
#   - Lambda function (packaged from scripts/aggregator/)
#   - CloudWatch log group with configurable retention
#   - EventBridge rule to trigger Lambda on schedule
# =============================================================================

# ---------------------------------------------------------------------------
# Lambda deployment package
# ---------------------------------------------------------------------------

data "archive_file" "aggregator" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/files/aggregator.zip"
  excludes    = ["__pycache__", "*.pyc", "test_*.py", "*.egg-info"]
}

# ---------------------------------------------------------------------------
# IAM role for Lambda
# ---------------------------------------------------------------------------

resource "aws_iam_role" "aggregator" {
  name = "${var.project_name}-aggregator"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "aggregator_permissions" {
  name = "${var.project_name}-aggregator-permissions"
  role = aws_iam_role.aggregator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 — write findings
      {
        Sid    = "WriteFindings"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          var.findings_bucket_arn,
          "${var.findings_bucket_arn}/*",
        ]
      },
      # Security Hub — read findings
      {
        Sid    = "ReadSecurityHub"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:ListFindingAggregators",
        ]
        Resource = "*"
      },
      # IAM Access Analyzer — read findings
      {
        Sid    = "ReadAccessAnalyzer"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding",
          "access-analyzer:ListAnalyzers",
        ]
        Resource = "*"
      },
      # IAM — enumerate users, roles, access keys
      {
        Sid    = "ReadIAM"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListRoles",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetailsWithEntities",
        ]
        Resource = "*"
      },
      # CloudTrail — look up events for SCP violations
      {
        Sid    = "ReadCloudTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
        ]
        Resource = "*"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch log group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "aggregator" {
  name              = "/aws/lambda/${var.project_name}-aggregator"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "aggregator" {
  function_name    = "${var.project_name}-aggregator"
  description      = "Aggregates IAM findings from Security Hub, Access Analyzer, IAM API, and CloudTrail into S3"
  role             = aws_iam_role.aggregator.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  filename         = data.archive_file.aggregator.output_path
  source_code_hash = data.archive_file.aggregator.output_base64sha256
  tags             = var.tags

  environment {
    variables = {
      FINDINGS_BUCKET        = var.findings_bucket_name
      ANALYZER_ARN           = var.analyzer_arn
      KEY_AGE_THRESHOLD_DAYS = tostring(var.key_age_threshold_days)
      IAM_DASHBOARD_REGION   = var.aws_region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.aggregator,
    aws_iam_role_policy_attachment.basic_execution,
    aws_iam_role_policy.aggregator_permissions,
  ]
}

# ---------------------------------------------------------------------------
# EventBridge rule — scheduled trigger
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "aggregator_schedule" {
  name                = "${var.project_name}-aggregator-schedule"
  description         = "Triggers the IAM findings aggregator Lambda on a daily schedule"
  schedule_expression = var.schedule_expression
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "aggregator" {
  rule      = aws_cloudwatch_event_rule.aggregator_schedule.name
  target_id = "iam-findings-aggregator"
  arn       = aws_lambda_function.aggregator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.aggregator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.aggregator_schedule.arn
}
