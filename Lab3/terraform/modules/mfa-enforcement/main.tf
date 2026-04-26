# =============================================================================
# MFA Enforcement Module
# Requires MFA for destructive actions
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# MFA Required Policy for Destructive Actions
resource "aws_iam_policy" "require_mfa_destructive" {
  name        = "${var.project_name}-require-mfa-destructive"
  description = "Requires MFA for destructive actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyEC2TerminateWithoutMFA"
        Effect = "Deny"
        Action = [
          "ec2:TerminateInstances",
          "ec2:DeleteVolume",
          "ec2:DeleteSnapshot"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyS3DeleteWithoutMFA"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "s3:DeleteObject"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyRDSDeleteWithoutMFA"
        Effect = "Deny"
        Action = [
          "rds:DeleteDBInstance",
          "rds:DeleteDBCluster",
          "rds:DeleteDBSnapshot"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyIAMDeleteWithoutMFA"
        Effect = "Deny"
        Action = [
          "iam:DeleteUser",
          "iam:DeleteRole",
          "iam:DeletePolicy"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyKMSDeleteWithoutMFA"
        Effect = "Deny"
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteAlias"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "DenyLambdaDeleteWithoutMFA"
        Effect = "Deny"
        Action = [
          "lambda:DeleteFunction"
        ]
        Resource = var.protected_resources
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name        = "${var.project_name}-require-mfa-destructive"
    Environment = var.environment
  })
}

# IAM Group with MFA enforcement
resource "aws_iam_group" "mfa_enforced" {
  name = "${var.project_name}-mfa-enforced-group"
}

resource "aws_iam_group_policy_attachment" "mfa_enforced" {
  group      = aws_iam_group.mfa_enforced.name
  policy_arn = aws_iam_policy.require_mfa_destructive.arn
}

# Self-service MFA management policy
resource "aws_iam_policy" "self_manage_mfa" {
  name        = "${var.project_name}-self-manage-mfa"
  description = "Allows users to manage their own MFA devices"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnVirtualMFADevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = "arn:aws:iam::${var.account_id}:mfa/
$$
{aws:username}"
      },
      {
        Sid    = "AllowManageOwnUserMFA"
        Effect = "Allow"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = "arn:aws:iam::${var.account_id}:user/
$$
{aws:username}"
      },
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name        = "${var.project_name}-self-manage-mfa"
    Environment = var.environment
  })
}

resource "aws_iam_group_policy_attachment" "self_manage_mfa" {
  group      = aws_iam_group.mfa_enforced.name
  policy_arn = aws_iam_policy.self_manage_mfa.arn
}