# IAM Permission Auditor

A Python tool to identify unused IAM permissions by analyzing AWS IAM service last accessed data.

## Overview

This tool helps implement the principle of least privilege by identifying IAM roles and users with permissions to services they haven't accessed within a configurable time threshold (default: 90 days).

## Features

- **Service Last Accessed Analysis**: Uses IAM's `GenerateServiceLastAccessedDetails` API
- **Multi-Entity Support**: Audits both IAM roles and users
- **Cross-Account Auditing**: Support for auditing multiple AWS accounts
- **Lambda Ready**: Can be deployed as an AWS Lambda function
- **Flexible Output**: JSON reports, CLI summaries, S3 storage
- **Notifications**: SNS integration for alerts

## Installation

### Local Installation

```bash
# Clone the repository
cd scripts/iam-audit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt