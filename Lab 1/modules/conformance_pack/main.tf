terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_config_conformance_pack" "this" {
  name          = var.name
  template_body = var.template_body
}