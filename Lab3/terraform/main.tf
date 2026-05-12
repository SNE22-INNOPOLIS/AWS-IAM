# =============================================================================
# Main Terraform Configuration
# Lab 3: IAM Preventative Guardrails
# =============================================================================

data "aws_caller_identity" "security" {
  provider = aws.security
}

data "aws_caller_identity" "dev" {
  provider = aws.dev
}

# =============================================================================
# KEEP LAB 1 & LAB 2 MODULES HERE (your existing modules)
# =============================================================================

# ... (Include all your Lab1 and Lab2 module blocks here)

# =============================================================================
# LAB 3: Permission Boundaries - Security Account
# =============================================================================

module "permission_boundaries_security" {
  source = "./modules/permission-boundaries"

  providers = {
    aws = aws.security
  }

  account_id   = var.security_account_id
  account_name = "security"
  project_name = var.project_name
  environment  = var.environment

  tags = {
    Account = "Security"
  }
}

# =============================================================================
# LAB 3: Permission Boundaries - Dev Account
# =============================================================================

module "permission_boundaries_dev" {
  source = "./modules/permission-boundaries"

  providers = {
    aws = aws.dev
  }

  account_id   = var.dev_account_id
  account_name = "dev"
  project_name = var.project_name
  environment  = var.environment

  tags = {
    Account = "Dev"
  }
}

# =============================================================================
# LAB 3: MFA Enforcement Policy - Security Account
# =============================================================================

module "mfa_enforcement_security" {
  source = "./modules/mfa-enforcement"

  providers = {
    aws = aws.security
  }

  account_id          = var.security_account_id
  account_name        = "security"
  project_name        = var.project_name
  protected_resources = var.protected_resources
  environment         = var.environment

  tags = {
    Account = "Security"
  }
}

# =============================================================================
# LAB 3: MFA Enforcement Policy - Dev Account
# =============================================================================

module "mfa_enforcement_dev" {
  source = "./modules/mfa-enforcement"

  providers = {
    aws = aws.dev
  }

  account_id          = var.dev_account_id
  account_name        = "dev"
  project_name        = var.project_name
  protected_resources = var.protected_resources
  environment         = var.environment

  tags = {
    Account = "Dev"
  }
}

# =============================================================================
# LAB 3: Guardrail Enforcement Lambda - Dev Account
# =============================================================================

module "guardrail_enforcement_lambda_dev" {
  source = "./modules/guardrail-enforcement-lambda"

  providers = {
    aws = aws.dev
  }

  account_id                = var.dev_account_id
  account_name              = "dev"
  project_name              = var.project_name
  permission_boundary_arn   = module.permission_boundaries_dev.boundary_policy_arn
  enable_auto_remediation   = var.enable_auto_remediation
  notification_email        = var.notification_email
  environment               = var.environment

  tags = {
    Account = "Dev"
  }

  depends_on = [module.permission_boundaries_dev]
}

# =============================================================================
# LAB 3: Config Rules for Guardrails - Dev Account
# =============================================================================

module "config_rules_guardrails_dev" {
  source = "./modules/config-rules-guardrails"

  providers = {
    aws = aws.dev
  }

  account_id              = var.dev_account_id
  account_name            = "dev"
  project_name            = var.project_name
  permission_boundary_arn = module.permission_boundaries_dev.boundary_policy_arn
  environment             = var.environment

  tags = {
    Account = "Dev"
  }

  depends_on = [module.permission_boundaries_dev]
}

# =============================================================================
# LAB 3: BreakGlass Role - Security Account
# =============================================================================

module "breakglass_security" {
  source = "./modules/breakglass"

  providers = {
    aws = aws.security
  }

  account_id       = var.security_account_id
  account_name     = "security"
  project_name     = var.project_name
  existing_group_name    = var.security_breakglass_group_name 
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  sns_topic_arn    = aws_sns_topic.guardrail_alerts.arn
  notification_email     = var.notification_email
  environment      = var.environment

  tags = {
    Account = "Security"
    Purpose = "BreakGlass"
  }
}

# =============================================================================
# LAB 3: BreakGlass Role - Dev Account
# =============================================================================

module "breakglass_dev" {
  source = "./modules/breakglass"

  providers = {
    aws = aws.dev
  }

  account_id       = var.dev_account_id
  account_name     = "dev"
  project_name     = var.project_name
  existing_group_name    = var.dev_breakglass_group_name 
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  cross_account_role_arn = module.breakglass_security.breakglass_role_arn
  sns_topic_arn    = aws_sns_topic.guardrail_alerts.arn
  notification_email     = var.notification_email
  environment      = var.environment

  tags = {
    Account = "Dev"
    Purpose = "BreakGlass"
  }

  depends_on = [module.breakglass_security]
}

# =============================================================================
# LAB 3: SNS Topic for Guardrail Alerts
# =============================================================================

resource "aws_sns_topic" "guardrail_alerts" {
  provider = aws.security
  name     = "${var.project_name}-alerts"

  tags = {
    Purpose = "Guardrail Violation Alerts"
  }
}

resource "aws_sns_topic_subscription" "guardrail_email" {
  count     = var.notification_email != "" ? 1 : 0
  provider  = aws.security
  topic_arn = aws_sns_topic.guardrail_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sns_topic_policy" "guardrail_alerts_policy" {
  provider = aws.security
  arn      = aws_sns_topic.guardrail_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCrossAccountPublish"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${var.security_account_id}:root",
            "arn:aws:iam::${var.dev_account_id}:root"
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardrail_alerts.arn
      }
    ]
  })
}