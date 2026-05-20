# Lab 3 — IAM Preventative Guardrails

This lab implements **preventative guardrails** at the AWS account level to stop dangerous IAM actions before they happen. Controls are enforced through Permission Boundaries, Conditional IAM Policies, an automated enforcement Lambda, and AWS Config Rules — all version-controlled and deployed via Terraform.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How the Guardrails Work](#how-the-guardrails-work)
3. [Module Structure](#module-structure)
4. [Prerequisites](#prerequisites)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Testing](#testing)
8. [Break Glass Access](#break-glass-access)
9. [Monitoring and Alerts](#monitoring-and-alerts)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Security Account                         │
│                    (865147226759)                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  BreakGlass IAM Role + CloudTrail Trail              │  │
│  │  Console Switch Role: Administrators group only      │  │
│  └────────────────────────┬─────────────────────────────┘  │
│                            │ cross-account assume            │
│  ┌──────────────────────┐  │                                │
│  │  SNS Alerts Topic    │◄─┘                                │
│  │  (Central)           │                                   │
│  └──────────┬───────────┘                                   │
└─────────────│───────────────────────────────────────────────┘
              │ email alerts
              ▼
┌─────────────────────────────────────────────────────────────┐
│                       Dev Account                            │
│                    (418272768233)                            │
│                                                             │
│  ┌──────────────────────┐   ┌──────────────────────────┐   │
│  │  Permission Boundary │   │   BreakGlass IAM Role    │   │
│  │  (enforced here)     │   │   + CloudTrail Trail     │   │
│  └──────────────────────┘   │   (cross-account only)   │   │
│                              └──────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Guardrails Module                        │  │
│  │                                                       │  │
│  │  ┌─────────────────────┐  ┌────────────────────────┐ │  │
│  │  │  Enforcement Lambda │  │  Config Rule Lambda    │ │  │
│  │  │  (auto-attach       │  │  (boundary checker)    │ │  │
│  │  │   boundaries)       │  └────────────────────────┘ │  │
│  │  └────────┬────────────┘                             │  │
│  │           │                                          │  │
│  │  ┌────────▼────────────┐  ┌────────────────────────┐ │  │
│  │  │  EventBridge Rules  │  │  AWS Config Rules (6)  │ │  │
│  │  │  CreateRole /       │  │  Boundary, MFA, Keys,  │ │  │
│  │  │  CreateUser         │  │  Password Policy...    │ │  │
│  │  └─────────────────────┘  └────────────────────────┘ │  │
│  │                                                       │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │  AWS Config Recorder + S3 Delivery Bucket        │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

> **Scope notes:**
> - The permission boundary is enforced only in the **Dev account**. The Security account has no enforcement Lambda or Config rules, so the boundary does not constrain principals there.
> - The Break Glass console Switch Role is available only in the **Security account** (via the `Administrators` group). Dev account users cannot assume the Dev Break Glass role directly; access requires cross-account assumption from the Security account's Break Glass role.

---

## How the Guardrails Work

### 1. Permission Boundary (`modules/permission-boundaries`)

A single IAM managed policy is attached to every IAM principal (user or role) in the account. It contains the following Deny statements — **all exempt if the principal carries the tag `Purpose=BreakGlass`**:

| Deny Sid | Actions Blocked | Condition |
|---|---|---|
| `DenyCreateUserWithoutBreakGlassTag` | `iam:CreateUser`, `iam:CreateAccessKey`, `iam:CreateLoginProfile` | Principal not tagged `Purpose=BreakGlass` |
| `DenyDestructiveActionsWithoutMFA` | `ec2:TerminateInstances`, `s3:DeleteBucket`, `rds:DeleteDBInstance` | MFA not present AND not BreakGlass |
| `DenyRemovingPermissionBoundary` | `iam:DeleteUserPermissionsBoundary`, `iam:PutRolePermissionsBoundary`, etc. | Not BreakGlass |
| `DenyChangingPermissionBoundaryPolicy` | `iam:CreatePolicyVersion`, `iam:DeletePolicy`, etc. on the boundary policy | Not BreakGlass |
| `DenyDisablingCloudTrail` | `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` | Not BreakGlass |
| `DenyDisablingConfig` | `config:StopConfigurationRecorder`, `config:DeleteDeliveryChannel` | Not BreakGlass |
| `DenyDeletingGuardrailResources` | `lambda:DeleteFunction`, `events:DeleteRule` on guardrail resources | Not BreakGlass |

The permission boundary policy is created in both accounts, but **active enforcement — automatic attachment via Lambda, EventBridge, and Config rule evaluation — runs only in the Dev account**. In the Security account the policy resource exists but no automation attaches it to principals.

### 2. Automatic Boundary Enforcement (`modules/guardrails`)

An EventBridge rule watches CloudTrail for `CreateRole` and `CreateUser` API calls. Any new principal that does not already have the boundary attached will have it applied automatically within seconds by the enforcement Lambda.

```
CloudTrail → EventBridge (CreateRole / CreateUser) → Lambda → PutRolePermissionsBoundary
```

The Lambda also exposes a `scan_all` action that can be invoked manually to remediate any existing non-compliant principals.

### 3. AWS Config Rules (`modules/guardrails`)

Six Config rules continuously evaluate IAM resources against the defined standards:

| Rule | Type | What it flags |
|---|---|---|
| `iam-guardrails-iam-role-boundary-check` | Custom Lambda | Roles missing the required permission boundary |
| `iam-guardrails-iam-user-mfa-enabled` | AWS Managed | Users without MFA enabled |
| `iam-guardrails-root-mfa-enabled` | AWS Managed | Root account without MFA |
| `iam-guardrails-iam-user-no-inline-policies` | AWS Managed | Users with inline policies attached |
| `iam-guardrails-access-keys-rotated` | AWS Managed | Access keys not rotated within 90 days |
| `iam-guardrails-iam-password-policy` | AWS Managed | Account password policy below minimum standards |

### 4. Break Glass Role (`modules/breakglass`)

An IAM role tagged `Purpose=BreakGlass` that bypasses all permission boundary Deny conditions. Every successful or failed assumption attempt triggers an immediate SNS email alert. See [docs/breakglass-procedure.md](docs/breakglass-procedure.md) for the full procedure.

**Account-specific behaviour:**

| Account | Role exists | Console Switch Role | Direct API/CLI assumption |
|---|---|---|---|
| Security (`865147226759`) | Yes | Yes — `Administrators` group has the assume policy; MFA required | Yes, with MFA |
| Dev (`418272768233`) | Yes | No — no local group has the assume policy | Only via cross-account assumption from the Security account's Break Glass role |

Dev account Break Glass access requires a two-hop chain: assume the Security Break Glass role first (with MFA), then assume the Dev Break Glass role from that session.

---

## Module Structure

```
Lab3/
├── docs/
│   └── breakglass-procedure.md       # Emergency access procedure
├── scripts/
│   └── guardrail-enforcement/
│       ├── lambda_function.py         # Boundary auto-attachment Lambda
│       ├── permission_boundary_checker.py  # Config rule custom Lambda
│       └── test_lambda.py             # Unit tests
└── terraform/
    ├── main.tf                        # Root module — wires everything together
    ├── variables.tf
    ├── outputs.tf
    ├── terraform.tfvars
    ├── providers.tf
    ├── backend.tf
    └── modules/
        ├── permission-boundaries/     # Permission boundary policy
        ├── guardrails/                # Lambda + Config rules + recorder
        └── breakglass/               # Break Glass role + alerting
```

---

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with two named profiles: `security` and `dev`
- MFA device enrolled on the IAM user used for deployment
- S3 bucket and DynamoDB table for Terraform state (see `backend.tf`)
- CloudTrail S3 bucket (`security-lab-central-cloudtrail-logs`) already exists — created in Lab 1

Verify profiles are working:

```bash
aws sts get-caller-identity --profile security
aws sts get-caller-identity --profile dev
```

---

## Configuration

All environment-specific values are set in `terraform/terraform.tfvars`:

| Variable | Description | Value |
|---|---|---|
| `security_account_id` | Security account AWS ID | `865147226759` |
| `dev_account_id` | Dev account AWS ID | `418272768233` |
| `security_account_profile` | AWS CLI profile for Security account | `security` |
| `dev_account_profile` | AWS CLI profile for Dev account | `dev` |
| `primary_region` | AWS region | `us-east-1` |
| `project_name` | Prefix for all resource names | `iam-guardrails` |
| `cloudtrail_bucket_name` | S3 bucket for CloudTrail logs | `security-lab-central-cloudtrail-logs` |
| `security_breakglass_group_name` | Existing IAM group granted Break Glass access | `Administrators` |
| `notification_email` | Email address for guardrail alerts | *(set in tfvars)* |
| `enable_auto_remediation` | Lambda auto-attaches boundaries when `true` | `true` |

---

## Deployment

```bash
cd Lab3/terraform

# 1. Initialise providers and remote state
terraform init

# 2. Validate configuration
terraform validate

# 3. Preview changes
terraform plan -out=tfplan

# 4. Apply
terraform apply tfplan
```

On completion, Terraform prints the key output values:

```
permission_boundary_security_arn    = "arn:aws:iam::865147226759:policy/iam-guardrails-permission-boundary"
permission_boundary_dev_arn         = "arn:aws:iam::418272768233:policy/iam-guardrails-permission-boundary"
breakglass_role_security_arn        = "arn:aws:iam::865147226759:role/iam-guardrails-breakglass-role"
breakglass_role_dev_arn             = "arn:aws:iam::418272768233:role/iam-guardrails-breakglass-role"
guardrail_enforcement_lambda_arn    = "arn:aws:lambda:us-east-1:418272768233:function:iam-guardrails-enforcement"
guardrail_alerts_topic_arn          = "arn:aws:sns:us-east-1:865147226759:iam-guardrails-alerts"
test_permission_boundary_command    = "aws iam create-user --user-name test-blocked-user --profile dev"
assume_breakglass_role_command      = "aws sts assume-role --role-arn ... --role-session-name breakglass-session --profile security"
```

---

## Testing

### Test 1 — Permission Boundary Blocks User Creation

Any principal without the `Purpose=BreakGlass` tag cannot create IAM users:

```bash
aws iam create-user --user-name test-blocked-user --profile dev
```

Expected response:

```
An error occurred (AccessDenied) when calling the CreateUser operation:
User is not authorized to perform: iam:CreateUser
```

---

### Test 2 — MFA Required for Destructive Actions

Attempting to terminate an EC2 instance without an active MFA session is blocked:

```bash
aws ec2 terminate-instances \
  --instance-ids i-1234567890abcdef0 \
  --profile dev
```

Expected response:

```
An error occurred (AccessDenied) when calling the TerminateInstances operation:
User is not authorized to perform: ec2:TerminateInstances
```

The same applies to `s3:DeleteBucket` and `rds:DeleteDBInstance`.

---

### Test 3 — Break Glass Role Bypasses Guardrails

```bash
# Step 1: Obtain an MFA session token from the Security account
aws sts get-session-token \
  --serial-number arn:aws:iam::865147226759:mfa/YOUR_USERNAME \
  --token-code 123456 \
  --profile security \
  --output json > /tmp/mfa-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/mfa-session.json)

# Step 2: Assume the Break Glass role in the Dev account
aws sts assume-role \
  --role-arn arn:aws:iam::418272768233:role/iam-guardrails-breakglass-role \
  --role-session-name test-breakglass \
  --output json > /tmp/breakglass-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/breakglass-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/breakglass-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/breakglass-session.json)

# Step 3: Create user — this should now succeed with Break Glass credentials
aws iam create-user --user-name emergency-user
```

---

### Test 4 — Trigger Enforcement Lambda

Manually invoke the Lambda to scan all existing roles and users and attach any missing boundaries:

```bash
aws lambda invoke \
  --function-name iam-guardrails-enforcement \
  --payload '{"action": "scan_all"}' \
  --cli-binary-format raw-in-base64-out \
  --profile dev \
  /tmp/enforcement-output.json

cat /tmp/enforcement-output.json | jq .
```

Expected output:

```json
{
  "statusCode": 200,
  "body": {
    "message": "Guardrail enforcement completed",
    "total_processed": 12,
    "successful": 12
  }
}
```

---

### Test 5 — Check Config Rule Compliance

```bash
aws configservice describe-compliance-by-config-rule \
  --region us-east-1 \
  --profile dev \
  --query 'ComplianceByConfigRules[?starts_with(ConfigRuleName, `iam-guardrails`)]' \
  --output table
```

Expected output shows each rule with a `COMPLIANT` or `NON_COMPLIANT` status. Any non-compliant finding includes an annotation explaining what is missing.

---

## Break Glass Access

Full procedure is documented in [docs/breakglass-procedure.md](docs/breakglass-procedure.md).

**Summary:**
1. Raise an incident ticket.
2. Obtain an MFA-authenticated session token from the **Security account**.
3. Assume `iam-guardrails-breakglass-role` in the Security account (console Switch Role or API).
4. If access to the Dev account is needed, cross-account assume `iam-guardrails-breakglass-role` in the Dev account from the Security session.
5. Perform only the minimum actions required.
6. Exit and clear credentials immediately after.
7. Submit a post-incident report.

> Console Switch Role is available **only in the Security account**. Dev account users cannot assume the Dev Break Glass role directly — there is no local assume policy in that account.
>
> Every assumption of the Break Glass role — successful or failed — triggers an immediate email alert to the security team via SNS.

---

## Monitoring and Alerts

| Alert | Trigger | Destination |
|---|---|---|
| Break Glass role assumed | EventBridge → `iam-guardrails-breakglass-success` | SNS email |
| Break Glass assumption failed (API) | EventBridge → `iam-guardrails-breakglass-failed` | SNS email |
| Break Glass switch failed (Console) | EventBridge → `iam-guardrails-breakglass-failed-console` | SNS email |
| Guardrail boundary auto-attached | Lambda log + SNS publish | SNS email |
| Config rule violation detected | AWS Config console + findings | AWS Config dashboard |

Query recent Break Glass activity in CloudTrail:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=iam-guardrails-breakglass-role \
  --region us-east-1 \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Event:EventName}' \
  --output table
```
