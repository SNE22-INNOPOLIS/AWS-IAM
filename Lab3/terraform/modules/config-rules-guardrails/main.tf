# =============================================================================
# Config Rules for Guardrails Module
# Detects non-compliant IAM entities
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Custom Config Rule: IAM Roles must have Permission Boundary
resource "aws_config_config_rule" "iam_role_permission_boundary" {
  name        = "${var.project_name}-iam-role-boundary-check"
  description = "Checks if IAM roles have the required permission boundary attached"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROLE_MANAGED_POLICY_CHECK"
  }

  input_parameters = jsonencode({
    managedPolicyArns = var.permission_boundary_arn
  })

  scope {
    compliance_resource_types = ["AWS::IAM::Role"]
  }

  tags = merge(var.tags, {
    Name        = "${var.project_name}-iam-role-boundary-check"
    Environment = var.environment
  })
}

# Config Rule: IAM User MFA Enabled
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
}

# Config Rule: Root MFA Enabled
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
}

# Config Rule: No IAM User Access Keys
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
}

# Config Rule: Access Keys Rotated
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
}

# Config Rule: IAM Password Policy
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
}