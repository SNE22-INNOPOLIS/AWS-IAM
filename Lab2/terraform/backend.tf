terraform {
  backend "s3" {
    bucket         = "security-lab-tfstate-security-account"
    key            = "security-lab/main/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "security-lab-tf-locks"
    profile        = "security"
  }
}