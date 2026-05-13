# =============================================================================
# BreakGlass Module
# - References existing IAM group
# - Local SNS topic per account for reliable notifications
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
# CloudTrail Configuration
# =============================================================================

resource "aws_cloudtrail" "breakglass_trail" {
  name                          = "${var.project_name}-breakglass-trail"
  s3_bucket_name                = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-breakglass-trail"
    Purpose = "BreakGlass Monitoring"
  })
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
# EventBridge Rule: Real-Time Alert on Failed Assumption (API/CLI)
# =============================================================================

resource "aws_cloudwatch_event_rule" "breakglass_failed" {
  name        = "${var.project_name}-breakglass-failed"
  description = "Real-time alert on failed Break Glass role assumption attempt (API/CLI)"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      errorCode   = [{exists = true}]
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

# =============================================================================
# EventBridge Rule: Real-Time Alert on Failed Console SwitchRole
# =============================================================================

resource "aws_cloudwatch_event_rule" "breakglass_failed_console" {
  name        = "${var.project_name}-breakglass-failed-console"
  description = "Real-time alert on failed Break Glass role switch attempt via AWS Console"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventSource = ["signin.amazonaws.com"]
      eventName   = ["SwitchRole"]
      errorMessage = [{exists = true}]
      additionalEventData = {
        SwitchTo = ["${aws_iam_role.breakglass.arn}*"]
      }
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-breakglass-failed-console-rule"
  })
}

resource "aws_cloudwatch_event_target" "breakglass_failed_console_sns" {
  rule      = aws_cloudwatch_event_rule.breakglass_failed_console.name
  target_id = "breakglass-failed-console-sns"
  arn       = aws_sns_topic.breakglass_alerts.arn
  role_arn  = aws_iam_role.eventbridge_sns.arn

  input_transformer {
    input_paths = {
      account    = "$.account"
      time       = "$.time"
      user       = "$.detail.userIdentity.arn"
      sourceIP   = "$.detail.sourceIPAddress"
      region     = "$.region"
      errorMsg   = "$.detail.errorMessage"
      switchTo   = "$.detail.additionalEventData.SwitchTo"
    }
    input_template = <<-EOF
      "================================================"
      "SECURITY ALERT: Break Glass Console FAILED Attempt"
      "================================================"
      "Account        : <account>"
      "Region         : <region>"
      "Time           : <time>"
      "User           : <user>"
      "Source IP      : <sourceIP>"
      "Attempted Role : <switchTo>"
      "Error Message  : <errorMsg>"
      "------------------------------------------------"
      "ACTION REQUIRED: Investigate unauthorized Break Glass console access attempt immediately."
      "================================================"
    EOF
  }

  depends_on = [
    aws_sns_topic_policy.breakglass_alerts,
    aws_iam_role_policy.eventbridge_sns
  ]
}