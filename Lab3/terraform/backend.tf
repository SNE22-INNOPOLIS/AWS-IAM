terraform {
  backend "s3" {
    bucket         = "security-lab-tfstate-security-account"
    key            = "security-lab/lab3/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "security-lab-tf-locks"
    encrypt        = true
    profile        = "security"
  }
}