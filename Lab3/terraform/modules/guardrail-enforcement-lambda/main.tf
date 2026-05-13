# =============================================================================
# Guardrail Enforcement Lambda Module
# Automatically attaches permission boundaries to new IAM entities
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
  name = "${var.project_name}-enforcement-lambda-role"

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
    Name = "${var.project_name}-enforcement-lambda-role"
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-enforcement-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMEnforcement"
        Effect = "Allow"
        Action = [
          "iam:PutRolePermissionsBoundary",
          "iam:PutUserPermissionsBoundary",
          "iam:GetRole",
          "iam:GetUser",
          "iam:ListRoles",
          "iam:ListUsers",
          "iam:TagRole",
          "iam:TagUser"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = "*"
      }
    ]
  })
}

# Package Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/guardrail-enforcement"
  output_path = "${path.module}/files/guardrail_enforcement_${var.account_name}.zip"
  excludes    = ["test_lambda.py", "__pycache__", "*.pyc", "requirements.txt"]
}

# Lambda function
resource "aws_lambda_function" "enforcement" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-enforcement"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      PERMISSION_BOUNDARY_ARN = var.permission_boundary_arn
      ACCOUNT_ID              = var.account_id
      ENABLE_REMEDIATION      = tostring(var.enable_auto_remediation)
      SNS_TOPIC_ARN           = var.sns_topic_arn
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-enforcement"
  })

  depends_on = [
    aws_iam_role_policy.lambda_policy
  ]
}

# EventBridge Rule for IAM Role Creation
resource "aws_cloudwatch_event_rule" "iam_role_created" {
  name        = "${var.project_name}-iam-role-created"
  description = "Triggers on IAM Role creation"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateRole"]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-iam-role-created"
  })
}

resource "aws_cloudwatch_event_target" "iam_role_created" {
  rule      = aws_cloudwatch_event_rule.iam_role_created.name
  target_id = "guardrail-enforcement"
  arn       = aws_lambda_function.enforcement.arn
}

resource "aws_lambda_permission" "allow_eventbridge_role" {
  statement_id  = "AllowEventBridgeRole"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enforcement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_role_created.arn
}

# EventBridge Rule for IAM User Creation
resource "aws_cloudwatch_event_rule" "iam_user_created" {
  name        = "${var.project_name}-iam-user-created"
  description = "Triggers on IAM User creation"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateUser"]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-iam-user-created"
  })
}

resource "aws_cloudwatch_event_target" "iam_user_created" {
  rule      = aws_cloudwatch_event_rule.iam_user_created.name
  target_id = "guardrail-enforcement"
  arn       = aws_lambda_function.enforcement.arn
}

resource "aws_lambda_permission" "allow_eventbridge_user" {
  statement_id  = "AllowEventBridgeUser"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enforcement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_user_created.arn
}