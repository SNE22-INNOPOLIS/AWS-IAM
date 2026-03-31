output "security_account_id" {
  value = aws_organizations_account.security.id
}

output "dev_account_id" {
  value = aws_organizations_account.dev.id
}

output "org_id" {
  value = aws_organizations_organization.main.id
}