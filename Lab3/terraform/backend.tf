backend "s3" {
  bucket         = "security-lab-tfstate-security-account"
  key            = "security-lab/lab3/terraform.tfstate"
  region         = "us-east-1"
  profile        = "security"
  encrypt        = true
  dynamodb_table = "security-lab-tfstate-lock"
}