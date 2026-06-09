terraform {
  # Use the backend from Lab1
  backend "s3" {
    bucket         = "security-lab-tfstate-security-account"
    key            = "security-lab/lab5/terraform.tfstate"
    region         = "us-east-1"
    use_lockfile   = true
    encrypt        = true
    profile        = "security"
  }
}
