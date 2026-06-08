terraform {
  backend "s3" {
    bucket         = "security-lab-terraform-state"
    key            = "lab5/iam-dashboard/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "security-lab-terraform-locks"
    encrypt        = true
    profile        = "security"
  }
}
