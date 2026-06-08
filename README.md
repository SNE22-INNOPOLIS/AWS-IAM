# AWS IAM Cloud Security Portfolio

A production-grade, multi-account AWS security engineering portfolio implemented entirely in Terraform. The repository walks through a progressive series of labs — from foundational audit infrastructure to automated preventative guardrails — across a two-account AWS environment (Security and Dev).

Each lab is self-contained, builds on the previous one, and is tracked against a GitHub issue.

---

## Executive Summary

| Lab | Title | GitHub Issue | Status |
|-----|-------|-------------|--------|
| [Lab 1](Lab1/) | Multi-Account Security Foundation | [[INFRA] Provision Multi-Account Security Lab Environment](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/1) | Complete |
| [Lab 2](Lab2/) | IAM Access Analyzer & Unused Permission Report | [[POLICY] Implement IAM Access Analyzer & Unused Permission Report](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/2) | Complete |
| [Lab 3](Lab3/) | IAM Preventative Guardrails | [[GOVERNANCE] Deploy Service Control Policies (SCPs) for Guardrails](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/3) | Complete |
| [Lab 4 ](https://github.com/SNE22-INNOPOLIS/AWS-IAM/tree/main/Lab4)| Automated Credential Rotation Lambda | [[AUTOMATE] Build Automated Credential Rotation Lambda](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/4) | Planned |
| Lab 5 | Security Posture Dashboard | [[VISUALIZE] Create Security Posture Dashboard (QuickSight/Security Hub)](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/5) | Planned |
| Lab 6 | Architecture Diagram & Operational Runbook | [[DOCUMENT] Architecture Diagram & Operational Runbook](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/6) | Planned |
| Lab 7 | Security Validation & Penetration Test | [[TEST] Security Validation & Penetration Test](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/7) | Planned |

---

## Account Architecture

All labs target a two-account AWS organisation structure:

| Account | Purpose | AWS Account ID |
|---------|---------|----------------|
| Security | Central logging, Break Glass roles, SNS alerts, Terraform state | `1111111111111` |
| Dev | Workload account — guardrails enforced, IAM audit targets | `2222222222222` |

AWS CLI profiles used throughout: `security` and `dev`.  
Primary region: `us-east-1`.

---

## Repository Structure

```
AWS-IAM/
├── Lab1/                          # Multi-account security foundation
│   ├── bootstrap/                 # S3 backend + DynamoDB state lock
│   ├── modules/
│   │   ├── central_logging/       # Centralised S3 buckets (CloudTrail + Config)
│   │   ├── account_cloudtrail/    # Per-account CloudTrail trail
│   │   ├── account_config/        # Per-account AWS Config recorder
│   │   └── conformance_pack/      # IAM best-practice conformance pack
│   ├── conformance-packs/
│   │   └── iam-conformance-pack.yaml
│   └── main.tf / variables.tf / outputs.tf
│
├── Lab2/                          # IAM access analysis and audit
│   ├── scripts/iam-audit/
│   │   ├── lambda_function.py     # Lambda handler
│   │   ├── local_runner.py        # CLI audit runner
│   │   └── test_lambda.py
│   └── terraform/
│       └── modules/
│           ├── iam-access-analyzer/
│           ├── iam-audit-lambda/
│           └── s3-reports-bucket/
│
└── Lab3/                          # Preventative guardrails
    ├── docs/
    │   └── breakglass-procedure.md
    ├── scripts/guardrail-enforcement/
    │   ├── lambda_function.py     # Boundary auto-attachment Lambda
    │   └── permission_boundary_checker.py  # Config rule Lambda
    └── terraform/
        └── modules/
            ├── permission-boundaries/
            ├── guardrails/
            └── breakglass/
```

---

## Lab Summaries

### Lab 1 — Multi-Account Security Foundation

**Issue:** [#1 — [INFRA] Provision Multi-Account Security Lab Environment](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/1)  
**Directory:** [Lab1/](Lab1/)

Establishes the shared infrastructure that every subsequent lab depends on.

- Central S3 buckets in the Security account for CloudTrail and AWS Config log delivery from both accounts.
- Multi-region CloudTrail trails enabled in both Security and Dev accounts, shipping to the central bucket.
- AWS Config recorders and delivery channels in both accounts.
- IAM best-practice conformance pack deployed to both accounts.
- Bootstrap module creates the S3 backend bucket and DynamoDB state-lock table for all future Terraform workspaces.

**Key dependency for later labs:** The CloudTrail bucket (`security-lab-central-cloudtrail-logs`) is referenced by Labs 2 and 3.

---

### Lab 2 — IAM Access Analyzer & Unused Permission Report

**Issue:** [#2 — [POLICY] Implement IAM Access Analyzer & Unused Permission Report](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/2)  
**Directory:** [Lab2/](Lab2/)  
**Lab README:** [Lab2/README.md](Lab2/README.md)

Adds visibility into over-permissioned IAM identities.

- IAM Access Analyzer enabled in both accounts to surface externally accessible resources.
- Scheduled Lambda function that queries IAM service-last-accessed data and flags roles/users with permissions unused for more than 90 days.
- Reports stored as JSON in an S3 bucket, with the latest report always written to a fixed `latest.json` key.
- Local CLI runner (`local_runner.py`) for running the same audit offline without deploying Lambda.

---

### Lab 3 — IAM Preventative Guardrails

**Issue:** [#3 — [GOVERNANCE] Deploy Service Control Policies (SCPs) for Guardrails](https://github.com/SNE22-INNOPOLIS/AWS-IAM/issues/3)  
**Directory:** [Lab3/](Lab3/)  
**Lab README:** [Lab3/README.md](Lab3/README.md)

Shifts from detection to prevention — blocking dangerous IAM actions before they happen.

- **Permission Boundary** (`modules/permission-boundaries`): An IAM managed policy attached to every principal in the Dev account. Denies user creation, removal of the boundary itself, disabling of CloudTrail/Config, deletion of guardrail Lambda/EventBridge resources, and destructive actions (`ec2:TerminateInstances`, `s3:DeleteBucket`, `rds:DeleteDBInstance`) without MFA. All deny conditions are bypassed by principals carrying the `Purpose=BreakGlass` tag. *Enforcement applies to the Dev account only; the Security account has no enforcement Lambda.*
- **Enforcement Lambda** (`modules/guardrails`): EventBridge rules watch for `CreateRole` and `CreateUser` CloudTrail events in the Dev account; the Lambda automatically attaches the permission boundary within seconds. A `scan_all` invocation remediates existing non-compliant principals.
- **AWS Config Rules** (`modules/guardrails`): Six rules (one custom Lambda, five AWS-managed) continuously evaluate IAM compliance in the Dev account: permission boundary presence, MFA enablement, root MFA, inline policies, key rotation, and password policy.
- **Break Glass Role** (`modules/breakglass`): An emergency IAM role tagged `Purpose=BreakGlass` that bypasses all boundary deny conditions. Console Switch Role is available only in the Security account (via the `Administrators` group with an MFA-required assume policy). Dev account Break Glass access requires cross-account assumption from the Security account's Break Glass role. Every assumption attempt triggers an SNS email alert.

---

## Prerequisites (All Labs)

- Terraform >= 1.5.0
- AWS CLI configured with two named profiles (`security` and `dev`)
- MFA device enrolled on the deploying IAM user
- Sufficient IAM permissions in both accounts (IAM, Lambda, S3, CloudTrail, Config, EventBridge, SNS)

Verify access before starting:

```bash
aws sts get-caller-identity --profile security
aws sts get-caller-identity --profile dev
```

---

## Getting Started

Labs must be deployed in order — each builds on resources created by the previous one.

```bash
# Step 1 — Bootstrap Terraform state (first time only)
cd Lab1/bootstrap/backend
terraform init && terraform apply

# Step 2 — Deploy Lab 1
cd ../../
terraform init
terraform apply

# Step 3 — Deploy Lab 2
cd ../Lab2/terraform
terraform init
terraform apply

# Step 4 — Deploy Lab 3
cd ../../Lab3/terraform
terraform init
terraform apply
```

Refer to the individual lab READMEs for detailed configuration and testing instructions.

---

## Teardown

Destroy in reverse order to respect cross-lab dependencies.

```bash
cd Lab3/terraform && terraform destroy
cd ../../Lab2/terraform && terraform destroy
cd ../../Lab1 && terraform destroy
```

> **Note:** The Lab 3 permission boundary may be attached to IAM principals by the enforcement Lambda at runtime. If `terraform destroy` fails with a `DeleteConflict` error on the boundary policy, strip the boundary from all affected principals first:
>
> ```bash
> POLICY_ARN="arn:aws:iam::418272768233:policy/iam-guardrails-permission-boundary"
> aws iam list-roles --profile dev --output json | \
>   jq -r ".Roles[] | select(.PermissionsBoundary.PermissionsBoundaryArn == \"$POLICY_ARN\") | .RoleName" | \
>   while read -r role; do
>     aws iam delete-role-permissions-boundary --role-name "$role" --profile dev --region us-east-1
>   done
> aws iam list-users --profile dev --output json | \
>   jq -r ".Users[] | select(.PermissionsBoundary.PermissionsBoundaryArn == \"$POLICY_ARN\") | .UserName" | \
>   while read -r user; do
>     aws iam delete-user-permissions-boundary --user-name "$user" --profile dev --region us-east-1
>   done
> ```
> Then re-run `terraform destroy`.

---

## Security Considerations

- No AWS credentials or secrets are committed to this repository. The `.gitignore` excludes `*.tfvars` files containing sensitive values.
- Terraform remote state is stored in an S3 bucket with DynamoDB state locking; both are created by the Lab 1 bootstrap module.
- All destructive guardrail bypasses require an active MFA session.
- Break Glass role assumptions generate real-time SNS email alerts regardless of success or failure.
- IAM access keys older than 90 days are flagged as non-compliant by Lab 3 Config rules.
