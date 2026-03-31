variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "security_account_email" {
  description = "<Email for Security-Tooling Account>"
  type        = string
  sensitive   = true
}

variable "dev_account_email" {
  description = "<Email for Dev-Workload Account>"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "<Environment Prefix>"
  type        = string
  default     = "sec-lab"
}