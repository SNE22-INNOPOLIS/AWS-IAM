# =============================================================================
# BreakGlass Module
# - References existing IAM group
# - Local SNS topic per account for reliable notifications
# - CloudTrail -> CloudWatch Logs integration for metric filters
# - EventBridge for real-time alerts on both success and failed attempts
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
data "aws_region" "current" {}

# =============================================================================
# Reference Existing IAM Group
# =============================================================================

data "aws_iam_group" "breakglass_group" {
  count      = var.existing_group_name != "" ? 1 : 0
  group_name = var.existing_group_name
}

# Attach assume role policy to the existing group
resource "aws_iam_group_policy" "breakglass_assume_role" {
  count = var.existing_group_name != "" ? 1 : 0

  name  = "${var.project_name}-breakglass-assume-policy"
  group = data.aws_iam_group.breakglass_group[0].group_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAssumeBreakGlassWithMFA"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.breakglass.arn
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
      {
        Sid      = "DenyAssumeBreakGlassWithoutMFA"
        Effect   = "Deny"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.breakglass.arn
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# =============================================================================
# BreakGlass IAM Role
# =============================================================================

resource "aws_iam_role" "breakglass" {
  name = "${var.project_name}-breakglass-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
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
      ],
      var.cross_account_role_arn != "" ? [
        {
          Sid    = "AllowCrossAccountBreakGlass"
          Effect = "Allow"
          Principal = {
            AWS = var.cross_account_role_arn
          }
          Action = "sts:AssumeRole"
        }
      ] : []
    )
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-breakglass-role"
    Purpose = "BreakGlass"
  })
}

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

# =============================================================================
# Local SNS Topic (Per Account - Avoids Cross-Account Permission Issues)
# =============================================================================

resource "aws_sns_topic" "breakglass_alerts" {
  name = "${var.project_name}-breakglass-alerts"

  tags = merge(var.tags, {
    Name    = "${var.project_name}-breakglass-alerts"
    Purpose = "BreakGlass Alerts"
  })
}

resource "aws_sns_topic_subscription" "breakglass_email" {
  count = var.notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.breakglass_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sns_topic_policy" "breakglass_alerts" {
  arn = aws_sns_topic.breakglass_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.breakglass_alerts.arn
      },
      {
        Sid    = "AllowEventBridge"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.breakglass_alerts.arn
      },
      {
        Sid    = "AllowAccountPublish"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.breakglass_alerts.arn
      }
    ]
  })
}

# =============================================================================
# CloudWatch Log Group for CloudTrail
# =============================================================================

resource "aws_cloudwatch_log_group" "breakglass_cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}-${var.account_id}"
  retention_in_days = 90

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cloudtrail-logs"
    Purpose = "BreakGlass CloudTrail Logs"
  })
}

# =============================================================================
# IAM Role: CloudTrail -> CloudWatch Logs
# =============================================================================

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-cloudtrail-cw-role"
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.breakglass_cloudtrail.arn}:*"
      }
    ]
  })
}

# =============================================================================
# CloudTrail with CloudWatch Logs Integration
# =============================================================================

resource "aws_cloudtrail" "breakglass_trail" {
  name                          = "${var.project_name}-breakglass-trail"
  s3_bucket_name                = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.breakglass_cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-breakglass-trail"
    Purpose = "BreakGlass Monitoring"
  })

  depends_on = [
    aws_cloudwatch_log_group.breakglass_cloudtrail,
    aws_iam_role_policy.cloudtrail_to_cloudwatch
  ]
}

# =============================================================================
# Metric Filter + Alarm: Successful Break Glass Assumption
# =============================================================================

resource "aws_cloudwatch_log_metric_filter" "breakglass_success" {
  name           = "${var.project_name}-breakglass-success"
  log_group_name = aws_cloudwatch_log_group.breakglass_cloudtrail.name
  pattern        = "{ ($.eventName = \"AssumeRole\") && ($.requestParameters.roleArn = \"${aws_iam_role.breakglass.arn}\") && ($.errorCode NOT EXISTS) }"

  metric_transformation {
    name          = "BreakGlassSuccess"
    namespace     = "SecurityMetrics/BreakGlass"
    value         = "1"
    default_value = "0"
  }

  depends_on = [
    aws_cloudwatch_log_group.breakglass_cloudtrail,
    aws_cloudtrail.breakglass_trail
  ]
}

resource "aws_cloudwatch_metric_alarm" "breakglass_success" {
  alarm_name          = "${var.project_name}-breakglass-success-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BreakGlassSuccess"
  namespace           = "SecurityMetrics/BreakGlass"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "ALERT: Break Glass role was successfully assumed in account ${var.account_id}"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.breakglass_alerts.arn]

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-success-alarm"
  })

  depends_on = [aws_sns_topic_policy.breakglass_alerts]
}

# =============================================================================
# Metric Filter + Alarm: Failed Break Glass Assumption
# =============================================================================

resource "aws_cloudwatch_log_metric_filter" "breakglass_failed" {
  name           = "${var.project_name}-breakglass-failed"
  log_group_name = aws_cloudwatch_log_group.breakglass_cloudtrail.name
  pattern        = "{ ($.eventName = \"AssumeRole\") && ($.errorCode = \"AccessDenied\") && ($.requestParameters.roleArn = \"${aws_iam_role.breakglass.arn}\") }"

  metric_transformation {
    name          = "BreakGlassFailed"
    namespace     = "SecurityMetrics/BreakGlass"
    value         = "1"
    default_value = "0"
  }

  depends_on = [
    aws_cloudwatch_log_group.breakglass_cloudtrail,
    aws_cloudtrail.breakglass_trail
  ]
}

resource "aws_cloudwatch_metric_alarm" "breakglass_failed" {
  alarm_name          = "${var.project_name}-breakglass-failed-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BreakGlassFailed"
  namespace           = "SecurityMetrics/BreakGlass"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "ALERT: Unauthorized Break Glass role assumption attempt in account ${var.account_id}"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.breakglass_alerts.arn]

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-failed-alarm"
  })

  depends_on = [aws_sns_topic_policy.breakglass_alerts]
}

# =============================================================================
# IAM Role: EventBridge -> SNS
# =============================================================================

resource "aws_iam_role" "eventbridge_sns" {
  name = "${var.project_name}-eventbridge-sns-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-eventbridge-sns-role"
  })
}

resource "aws_iam_role_policy" "eventbridge_sns" {
  name = "${var.project_name}-eventbridge-sns-policy"
  role = aws_iam_role.eventbridge_sns.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.breakglass_alerts.arn
      }
    ]
  })
}

# =============================================================================
# EventBridge Rule: Real-Time Alert on Successful Assumption
# =============================================================================

resource "aws_cloudwatch_event_rule" "breakglass_success" {
  name        = "${var.project_name}-breakglass-success"
  description = "Real-time alert when Break Glass role is successfully assumed"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AssumeRole"]
      requestParameters = {
        roleArn = ["${aws_iam_role.breakglass.arn}"]
      }
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-success-rule"
  })
}

resource "aws_cloudwatch_event_target" "breakglass_success_sns" {
  rule      = aws_cloudwatch_event_rule.breakglass_success.name
  target_id = "breakglass-success-sns"
  arn       = aws_sns_topic.breakglass_alerts.arn
  role_arn  = aws_iam_role.eventbridge_sns.arn

  input_transformer {
    input_paths = {
      account   = "$.account"
      time      = "$.time"
      user      = "$.detail.userIdentity.arn"
      sourceIP  = "$.detail.sourceIPAddress"
      region    = "$.region"
      roleArn   = "$.detail.requestParameters.roleArn"
      sessionName = "$.detail.requestParameters.roleSessionName"
    }
    input_template = <<-EOF
      "================================================"
      "SECURITY ALERT: Break Glass Role SUCCESSFULLY Assumed"
      "================================================"
      "Account   : <account>"
      "Region    : <region>"
      "Time      : <time>"
      "User      : <user>"
      "Source IP : <sourceIP>"
      "Role ARN  : <roleArn>"
      "Session   : <sessionName>"
      "------------------------------------------------"
      "ACTION REQUIRED: Verify this is an authorized emergency access."
      "Review CloudTrail logs immediately for all actions taken."
      "================================================"
    EOF
  }

  depends_on = [
    aws_sns_topic_policy.breakglass_alerts,
    aws_iam_role_policy.eventbridge_sns
  ]
}

# =============================================================================
# EventBridge Rule: Real-Time Alert on Failed Assumption
# =============================================================================

resource "aws_cloudwatch_event_rule" "breakglass_failed" {
  name        = "${var.project_name}-breakglass-failed"
  description = "Real-time alert on failed Break Glass role assumption attempt"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AssumeRole"]
      errorCode = ["AccessDenied", "MFAMethodNotAllowed"]
      requestParameters = {
        roleArn = ["${aws_iam_role.breakglass.arn}"]
      }
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-failed-rule"
  })
}

resource "aws_cloudwatch_event_target" "breakglass_failed_sns" {
  rule      = aws_cloudwatch_event_rule.breakglass_failed.name
  target_id = "breakglass-failed-sns"
  arn       = aws_sns_topic.breakglass_alerts.arn
  role_arn  = aws_iam_role.eventbridge_sns.arn

  input_transformer {
    input_paths = {
      account    = "$.account"
      time       = "$.time"
      user       = "$.detail.userIdentity.arn"
      sourceIP   = "$.detail.sourceIPAddress"
      region     = "$.region"
      errorCode  = "$.detail.errorCode"
      errorMsg   = "$.detail.errorMessage"
      roleArn    = "$.detail.requestParameters.roleArn"
    }
    input_template = <<-EOF
      "================================================"
      "SECURITY ALERT: Break Glass Role FAILED Attempt"
      "================================================"
      "Account     : <account>"
      "Region      : <region>"
      "Time        : <time>"
      "User        : <user>"
      "Source IP   : <sourceIP>"
      "Role ARN    : <roleArn>"
      "Error Code  : <errorCode>"
      "Error Detail: <errorMsg>"
      "------------------------------------------------"
      "ACTION REQUIRED: Investigate unauthorized Break Glass access attempt immediately."
      "================================================"
    EOF
  }

  depends_on = [
    aws_sns_topic_policy.breakglass_alerts,
    aws_iam_role_policy.eventbridge_sns
  ]
}