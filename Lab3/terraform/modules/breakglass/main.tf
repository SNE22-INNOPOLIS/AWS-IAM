# =============================================================================
# BreakGlass Module
# Emergency access role that bypasses guardrails
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# BreakGlass Role
resource "aws_iam_role" "breakglass" {
  name = "${var.project_name}-breakglass-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Allow specified users to assume
      length(var.breakglass_users) > 0 ? [
        {
          Sid    = "AllowBreakGlassUsers"
          Effect = "Allow"
          Principal = {
            AWS = var.breakglass_users
          }
          Action = "sts:AssumeRole"
          Condition = {
            Bool = {
              "aws:MultiFactorAuthPresent" = "true"
            }
          }
        }
      ] : [],
      # Allow cross-account assume from Security account
      var.cross_account_role_arn != "" ? [
        {
          Sid    = "AllowCrossAccountBreakGlass"
          Effect = "Allow"
          Principal = {
            AWS = var.cross_account_role_arn
          }
          Action = "sts:AssumeRole"
        }
      ] : [],
      # Default: Allow account root with MFA
      [
        {
          Sid    = "AllowAccountRootWithMFA"
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::${var.account_id}:root"
          }
          Action = "sts:AssumeRole"
          Condition = {
            Bool = {
              "aws:MultiFactorAuthPresent" = "true"
            }
          }
        }
      ]
    )
  })

  # Tag the role as BreakGlass to bypass permission boundary restrictions
  tags = merge(var.tags, {
    Name    = "${var.project_name}-breakglass-role"
    Purpose = "BreakGlass"
  })
}

# BreakGlass Policy - Full Admin Access
resource "aws_iam_role_policy" "breakglass_admin" {
  name = "${var.project_name}-breakglass-admin-policy"
  role = aws_iam_role.breakglass.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAdminAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Alarm for BreakGlass Role Usage
resource "aws_cloudwatch_log_metric_filter" "breakglass_usage" {
  name           = "${var.project_name}-breakglass-usage"
  pattern        = "{ $.eventName = \"AssumeRole\" && $.requestParameters.roleArn = \"${aws_iam_role.breakglass.arn}\" }"
  log_group_name = "aws-cloudtrail-logs-${var.account_id}"

  metric_transformation {
    name          = "BreakGlassRoleUsage"
    namespace     = "SecurityMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "breakglass_usage" {
  alarm_name          = "${var.project_name}-breakglass-usage-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BreakGlassRoleUsage"
  namespace           = "SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when BreakGlass role is assumed"
  treat_missing_data  = "notBreaching"

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-usage-alarm"
  })
}