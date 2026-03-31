# Update these values after running the bootstrap script
terraform {
  backend "s3" {
    bucket         = "terraform-state-security-lab-<INSERT_RANDOM_ID>"
    key            = "global/s3/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-state-locks"
    encrypt        = true
  }
}