output "topic_arn" {
  description = "ARN of the SNS topic used for rotation notifications"
  value       = aws_sns_topic.key_rotation.arn
}

output "topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.key_rotation.name
}
