resource "aws_organizations_organization" "main" {
  feature_set = "ALL"
}

resource "aws_organizations_account" "security" {
  name  = "Security-Tooling"
  email = var.security_account_email
}

resource "aws_organizations_account" "dev" {
  name  = "Dev-Workload"
  email = var.dev_account_email
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.main.roots[0].id
}