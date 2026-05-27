terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_sns_topic" "key_rotation" {
  name              = "${var.project_name}-key-rotation-${var.environment}"
  kms_master_key_id = var.kms_key_alias

  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.key_rotation.arn
  protocol  = "email"
  endpoint  = var.notification_email

  # AWS puts email subscriptions in PendingConfirmation until the link in the
  # confirmation email is clicked. If never confirmed, AWS deletes it after 72h.
  # prevent_destroy stops Terraform from recreating it on every apply, which
  # would re-trigger the confirmation email and reset the 72-hour window.
  lifecycle {
    prevent_destroy = true
  }
}
