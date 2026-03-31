resource "aws_cloudtrail" "org_trail" {
  name                          = "${var.environment}-org-trail"
  s3_bucket_name                = var.log_bucket_name
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
}

resource "aws_iam_role" "config_aggregator_role" {
  name = "${var.environment}-config-aggregator-role"

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
}

resource "aws_iam_role_policy_attachment" "config_aggregator_policy" {
  role       = aws_iam_role.config_aggregator_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_aggregator" "org_aggregator" {
  name = "${var.environment}-org-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator_role.arn
  }
}

resource "aws_config_conformance_pack" "iam_security_pack" {
  name       = "${var.environment}-iam-security-pack"
  template_s3_uri = "s3://awsexamplebucket/templates/ConformancePack/OperationalBestPracticesForIdentityManagement.json"
}