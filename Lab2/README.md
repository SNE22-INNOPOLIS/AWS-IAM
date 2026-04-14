# Multi-Account Security Lab - IAM Permission Analysis

A comprehensive Terraform-based security lab environment for identifying and analyzing unused IAM permissions across AWS accounts.

## 🎯 Objectives

1. **Enable IAM Access Analyzer** via Infrastructure as Code
2. **Identify Unused Permissions** using service last accessed data
3. **Generate Reports** of unused services per IAM role/user
4. **Support Multi-Account** analysis for enterprise environments

## 📋 Prerequisites

1. **Lab1 Completion**: This lab builds on Lab1's infrastructure:
   - S3 backend for Terraform state
   - DynamoDB table for state locking
   - AWS CLI profiles configured for both accounts

2. **AWS CLI Profiles**: Configure two profiles:
   ```bash
   # ~/.aws/credentials
   [security]
   aws_access_key_id = YOUR_SECURITY_ACCOUNT_KEY
   aws_secret_access_key = YOUR_SECURITY_ACCOUNT_SECRET

   [dev]
   aws_access_key_id = YOUR_DEV_ACCOUNT_KEY
   aws_secret_access_key = YOUR_DEV_ACCOUNT_SECRET
   ```

3. Required IAM Permissions: The deploying user needs permissions for:
- IAM (Access Analyzer, Roles, Policies)
- Lambda
- S3
- CloudWatch Events/Logs
- SNS (optional)


## 📁 Project Structure

Lab2/
├── terraform/
│   ├── main.tf                 # Main configuration
│   ├── variables.tf            # Input variables
│   ├── outputs.tf              # Output values
│   ├── provider.tf             # Provider configuration
│   ├── terraform.tfvars.example
│   └── modules/
│       ├── access-analyzer/    # IAM Access Analyzer module
│       └── iam-audit-lambda/   # Lambda function module
├── scripts/
│   └── iam-audit/
│       ├── lambda_function.py      # Lambda handler
│       ├── iam_audit_standalone.py # CLI tool
│       ├── requirements.txt
│       └── README.md
└── README.md

## 🚀 Quick Start

### 1. Clone and Configure

```bash
# Navigate to terraform directory
cd security-lab/terraform

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
vim terraform.tfvars
```

### 2. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan -out=tfplan

# Apply the configuration
terraform apply tfplan

# Save plan output for PR
terraform show -no-color tfplan > tfplan.txt
```

### 3. Test the Lambda Functions

```bash
# Invoke Security account Lambda
aws lambda invoke \
  --function-name iam-audit-lambda-security \
  --profile security \
  --region us-east-1 \
  /tmp/security-output.json

cat /tmp/security-output.json | jq .

# Invoke Dev account Lambda
aws lambda invoke \
  --function-name iam-audit-lambda-dev \
  --profile dev \
  --region us-east-1 \
  /tmp/dev-output.json

cat /tmp/dev-output.json | jq .
```

### 4. View Reports in S3

```bash
# List reports
aws s3 ls s3://iam-audit-reports-<account-id>/iam-audit-reports/ \
  --profile security --recursive

# Download latest report
aws s3 cp s3://iam-audit-reports-<account-id>/iam-audit-reports/security/latest.json \
  /tmp/latest.json --profile security

cat /tmp/latest.json | jq .
```


### 5. Run the Audit Locally

```bash
cd scripts/iam-audit

# Install dependencies
pip install -r requirements.txt

# Run against Security account
python local_runner.py \
  --profile security \
  --threshold-days 90 \
  --output /tmp/security-audit.json

# Run against Dev account with role filter
python local_runner.py \
  --profile dev \
  --role-filter iam-audit-test \
  --output /tmp/dev-audit.json

# Run unit tests
python -m pytest test_lambda.py -v
```
