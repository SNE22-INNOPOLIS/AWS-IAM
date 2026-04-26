# =============================================================================
# Permission Boundaries Module
# Restricts IAM actions unless tagged Purpose=BreakGlass
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

# Permission Boundary Policy
resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.project_name}-permission-boundary"
  description = "Permission boundary that restricts dangerous IAM actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAllActionsWithExceptions"
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      },
      {
        Sid    = "DenyCreateUserWithoutBreakGlassTag"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      },
      {
        Sid    = "DenyRemovingPermissionBoundary"
        Effect = "Deny"
        Action = [
          "iam:DeleteUserPermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary",
          "iam:PutUserPermissionsBoundary",
          "iam:PutRolePermissionsBoundary"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      },
      {
        Sid    = "DenyChangingPermissionBoundaryPolicy"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion"
        ]
        Resource = "arn:aws:iam::${var.account_id}:policy/${var.project_name}-permission-boundary"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      },
      {
        Sid    = "DenyDisablingCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      },
      {
        Sid    = "DenyDisablingConfig"
        Effect = "Deny"
        Action = [
          "config:StopConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      },
      {
        Sid    = "DenyDeletingGuardrailResources"
        Effect = "Deny"
        Action = [
          "lambda:DeleteFunction",
          "events:DeleteRule",
          "events:RemoveTargets"
        ]
        Resource = [
          "arn:aws:lambda:*:${var.account_id}:function:${var.project_name}-*",
          "arn:aws:events:*:${var.account_id}:rule/${var.project_name}-*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Purpose" = "BreakGlass"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name        = "${var.project_name}-permission-boundary"
    Environment = var.environment
  })
}

# IAM Role that must use this permission boundary
resource "aws_iam_role" "enforced_role_example" {
  name                 = "${var.project_name}-enforced-role-example"
  permissions_boundary = aws_iam_policy.permission_boundary.arn

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

  tags = merge(var.tags, {
    Name = "${var.project_name}-enforced-role-example"
  })
}