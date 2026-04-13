# Multi-Account Security Lab - IAM Permission Analysis

A comprehensive Terraform-based security lab environment for identifying and analyzing unused IAM permissions across AWS accounts.

## 🎯 Objectives

1. **Enable IAM Access Analyzer** via Infrastructure as Code
2. **Identify Unused Permissions** using service last accessed data
3. **Generate Reports** of unused services per IAM role/user
4. **Support Multi-Account** analysis for enterprise environments

## 📋 Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.5.0
- Python >= 3.9
- AWS Account(s) with IAM administrative access

## 📁 Project Structure

security-lab/
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
terraform plan

# Apply the configuration
terraform apply
```

### 3. Run Initial Audit

```bash
# Via AWS CLI
aws lambda invoke \
    --function-name iam-permission-auditor-lab \
    --payload '{"report_type": "full"}' \
    --cli-binary-format raw-in-base64-out \
    response.json

# View results
cat response.json | jq .
```

### 4. Run Standalone Script

```bash
cd scripts/iam-audit
pip install -r requirements.txt
python iam_audit_standalone.py --audit-all --threshold 90
```
