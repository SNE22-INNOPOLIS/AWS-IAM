# =============================================================================
# Guardrails Module
# Includes enforcement Lambda and AWS Config rules for Lab3
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
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Package Lambda code
resource "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/guardrail-enforcement"
  output_path = "${path.module}/files/guardrail_enforcement_${var.account_name}.zip"
  excludes    = ["test_lambda.py", "__pycache__", "*.pyc", "requirements.txt"]
}

resource "aws_lambda_function" "enforcement" {
  filename         = archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-enforcement"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = archive_file.lambda_zip.output_base64sha256
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

# =============================================================================
# AWS Config Recorder & Delivery Channel
# Required for any Config rule to evaluate resources.
# =============================================================================

resource "aws_s3_bucket" "config_bucket" {
  bucket        = "${var.project_name}-config-${var.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Name        = "${var.project_name}-config-bucket"
    Environment = var.environment
  })
}

resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket                  = aws_s3_bucket.config_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigGetAcl"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_bucket.arn
      },
      {
        Sid    = "AllowConfigPutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/${var.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.config_bucket]
}

resource "aws_iam_role" "config_recorder_role" {
  name = "${var.project_name}-config-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-config-recorder-role"
  })
}

resource "aws_iam_role_policy_attachment" "config_recorder_policy" {
  role       = aws_iam_role.config_recorder_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_recorder_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_recorder_policy]
}

resource "aws_config_delivery_channel" "channel" {
  name           = "${var.project_name}-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_configuration_recorder_status" "recorder" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.channel]
}

# =============================================================================
# Config Rules for non-compliant IAM resources
# =============================================================================

resource "aws_config_config_rule" "iam_role_permission_boundary" {
  name        = "${var.project_name}-iam-role-boundary-check"
  description = "Checks if IAM roles have the required permission boundary attached"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.permission_boundary_checker.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = ["AWS::IAM::Role"]
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-iam-role-boundary-check"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# Lambda function for custom Config rule
resource "aws_lambda_function" "permission_boundary_checker" {
  filename         = archive_file.permission_boundary_checker_zip.output_path
  function_name    = "${var.project_name}-permission-boundary-checker"
  role             = aws_iam_role.config_lambda_role.arn
  handler          = "permission_boundary_checker.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      PERMISSION_BOUNDARY_ARN = var.permission_boundary_arn
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-permission-boundary-checker"
  })
}

# Allow Config to invoke the Lambda function
resource "aws_lambda_permission" "config_invoke_permission" {
  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.permission_boundary_checker.function_name
  principal     = "config.amazonaws.com"
}

# IAM role for Config Lambda
resource "aws_iam_role" "config_lambda_role" {
  name = "${var.project_name}-config-lambda-role"

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
    Name = "${var.project_name}-config-lambda-role"
  })
}

resource "aws_iam_role_policy" "config_lambda_policy" {
  name = "${var.project_name}-config-lambda-policy"
  role = aws_iam_role.config_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:PutEvaluations"
        ]
        Resource = "*"
      }
    ]
  })
}

# Package the custom Config rule Lambda code
resource "archive_file" "permission_boundary_checker_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../scripts/guardrail-enforcement"
  output_path = "${path.module}/files/permission_boundary_checker.zip"
  excludes    = ["test_lambda.py", "__pycache__", "*.pyc", "requirements.txt", "lambda_function.py"]
}

resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  name        = "${var.project_name}-iam-user-mfa-enabled"
  description = "Checks if IAM users have MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-iam-user-mfa-enabled"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

resource "aws_config_config_rule" "root_mfa_enabled" {
  name        = "${var.project_name}-root-mfa-enabled"
  description = "Checks if root account has MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-root-mfa-enabled"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

resource "aws_config_config_rule" "iam_user_no_policies" {
  name        = "${var.project_name}-iam-user-no-inline-policies"
  description = "Checks that IAM users do not have inline policies"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-iam-user-no-inline-policies"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

resource "aws_config_config_rule" "access_keys_rotated" {
  name        = "${var.project_name}-access-keys-rotated"
  description = "Checks if access keys are rotated within 90 days"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  tags = merge(var.tags, {
    Name        = "${var.project_name}-access-keys-rotated"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

resource "aws_config_config_rule" "iam_password_policy" {
  name        = "${var.project_name}-iam-password-policy"
  description = "Checks if IAM password policy meets requirements"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })

  tags = merge(var.tags, {
    Name        = "${var.project_name}-iam-password-policy"
    Environment = var.environment
  })

  depends_on = [aws_config_configuration_recorder_status.recorder]
}
