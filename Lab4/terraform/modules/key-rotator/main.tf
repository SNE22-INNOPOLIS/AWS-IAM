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

data "aws_partition" "current" {}

locals {
  function_name = "${var.project_name}-credential-rotator-${var.environment}"
  log_group     = "/aws/lambda/${local.function_name}"
  partition     = data.aws_partition.current.partition
}

resource "aws_iam_role" "lambda" {
  name = "${local.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "key_management" {
  name = "${local.function_name}-key-management"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListAndInspectKeys"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
        ]
        Resource = "*"
      },
      {
        Sid    = "RotateAccessKeys"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
        ]
        Resource = "arn:${local.partition}:iam::${var.account_id}:user/*"
      },
      {
        Sid    = "StoreRotatedCredentials"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = "arn:${local.partition}:secretsmanager:${var.aws_region}:${var.account_id}:secret:${var.secret_prefix}/*"
      },
      {
        Sid      = "PublishRotationNotice"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.sns_topic_arn
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${local.partition}:logs:${var.aws_region}:${var.account_id}:log-group:${local.log_group}:*"
      },
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/files/credential-rotator.zip"
  excludes    = ["test_lambda.py", "__pycache__", "*.pyc"]
}

resource "aws_lambda_function" "rotator" {
  function_name    = local.function_name
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = var.lambda_runtime
  handler          = "lambda_function.lambda_handler"
  role             = aws_iam_role.lambda.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      ROTATION_AGE_DAYS = tostring(var.rotation_age_days)
      SNS_TOPIC_ARN     = var.sns_topic_arn
      SECRET_PREFIX     = var.secret_prefix
      PROTECTED_USERS   = jsonencode(var.protected_users)
      DRY_RUN           = tostring(var.dry_run)
    }
  }

  tags = var.tags

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_event_rule" "weekly_rotation" {
  name                = "${local.function_name}-schedule"
  description         = "Trigger IAM access key rotation check on schedule"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.weekly_rotation.name
  target_id = "CredentialRotatorLambda"
  arn       = aws_lambda_function.rotator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_rotation.arn
}
