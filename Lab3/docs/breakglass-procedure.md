# Break Glass Emergency Access Procedure

**Classification:** Internal — Security Operations  
**Owner:** Security Team  
**Last Reviewed:** 2026-05-20  
**Accounts in Scope:** Security (`865147226759`) · Dev (`418272768233`)

> **WARNING:** Break Glass access grants full administrative privileges and bypasses all preventative guardrails. Every action is logged in CloudTrail and triggers an immediate SNS alert to the security team. Use only in genuine emergencies.

---

## Table of Contents

1. [Active Guardrails](#1-active-guardrails)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — Document the Emergency](#3-step-1--document-the-emergency)
4. [Step 2 — Assume the Break Glass Role](#4-step-2--assume-the-break-glass-role)
5. [Step 3 — Perform Emergency Actions](#5-step-3--perform-emergency-actions)
6. [Step 4 — Exit the Break Glass Session](#6-step-4--exit-the-break-glass-session)
7. [Step 5 — Post-Incident Documentation](#7-step-5--post-incident-documentation)
8. [Monitoring and Alerts](#8-monitoring-and-alerts)
9. [Cross-Account Access](#9-cross-account-access)

---

## 1. Active Guardrails

The following preventative controls are enforced on every IAM principal in each account. Break Glass access is the **only** legitimate way to bypass them.

| Guardrail | Enforced By | Break Glass Exemption |
|---|---|---|
| `ec2:TerminateInstances` requires MFA | Permission boundary — `DenyDestructiveActionsWithoutMFA` | Role carries `Purpose=BreakGlass` tag; Deny condition does not apply |
| `s3:DeleteBucket` requires MFA | Permission boundary — `DenyDestructiveActionsWithoutMFA` | As above |
| `rds:DeleteDBInstance` requires MFA | Permission boundary — `DenyDestructiveActionsWithoutMFA` | As above |
| `iam:CreateUser` / `iam:CreateAccessKey` blocked | Permission boundary — `DenyCreateUserWithoutBreakGlassTag` | As above |
| CloudTrail and Config cannot be disabled | Permission boundary Deny statements | As above |
| New IAM roles automatically receive permission boundary | EventBridge → Lambda auto-remediation | Lambda exclusion list skips the Break Glass role |
| Non-compliant IAM entities reported | AWS Config custom and managed rules | Config rules continue to run independently |

### Why `iam:CreateUser` Returns AccessDenied

Every IAM principal created in a guardrailed account receives the `iam-guardrails-permission-boundary` automatically within seconds of creation (attached by the enforcement Lambda). That boundary includes:

```
Deny  iam:CreateUser, iam:CreateAccessKey, iam:CreateLoginProfile
  when  aws:PrincipalTag/Purpose != "BreakGlass"
```

A caller without the `Purpose=BreakGlass` tag attempting to create a user:

```bash
aws iam create-user --user-name test-blocked-user --profile dev
```

receives:

```
An error occurred (AccessDenied) when calling the CreateUser operation:
User: arn:aws:iam::418272768233:user/... is not authorized to perform:
iam:CreateUser because no identity-based policy allows the iam:CreateUser action.
```

The Break Glass role carries the tag `Purpose=BreakGlass`. Its sessions satisfy the `StringNotEquals` condition, so the Deny does not apply.

---

## 2. Prerequisites

Before initiating a Break Glass session, confirm all of the following:

- [ ] An MFA device is enrolled and accessible for your IAM user
- [ ] Your IAM user has been granted Break Glass access by the Security team
- [ ] An incident ticket has been raised (or is in progress)
- [ ] You have documented the business justification for emergency access

---

## 3. Step 1 — Document the Emergency

Complete the following **before** assuming the Break Glass role:

| Field | Details |
|---|---|
| Incident Ticket | e.g. `INC-20240115-001` |
| Justification | Brief description of the emergency |
| Target Account | Security / Dev |
| Approved By | Name of approving manager or security lead (if time permits) |
| Session Start Time (UTC) | |

> If the situation is too critical to obtain approval first, proceed and notify the security team immediately after assuming the role.

---

## 4. Step 2 — Assume the Break Glass Role

### Option A — AWS CLI

```bash
# ── Configuration ────────────────────────────────────────────────────────────
MFA_SERIAL="arn:aws:iam::ACCOUNT_ID:mfa/YOUR_USERNAME"
MFA_CODE="123456"                          # 6-digit TOTP code
BREAKGLASS_ROLE="arn:aws:iam::ACCOUNT_ID:role/iam-guardrails-breakglass-role"
SESSION_NAME="breakglass-$(whoami)-$(date +%Y%m%d%H%M%S)"

# ── Step 1: Obtain an MFA-authenticated session token ────────────────────────
aws sts get-session-token \
  --serial-number "${MFA_SERIAL}" \
  --token-code    "${MFA_CODE}" \
  --duration-seconds 3600 \
  --profile your-profile \
  --output json > /tmp/mfa-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/mfa-session.json)

# ── Step 2: Assume the Break Glass role ──────────────────────────────────────
aws sts assume-role \
  --role-arn         "${BREAKGLASS_ROLE}" \
  --role-session-name "${SESSION_NAME}" \
  --duration-seconds 3600 \
  --output json > /tmp/breakglass-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/breakglass-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/breakglass-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/breakglass-session.json)

# ── Step 3: Verify ───────────────────────────────────────────────────────────
aws sts get-caller-identity
```

**Expected output:**

```json
{
    "UserId": "AROAEXAMPLEID:breakglass-johndoe-20240115143000",
    "Account": "418272768233",
    "Arn": "arn:aws:sts::418272768233:assumed-role/iam-guardrails-breakglass-role/breakglass-johndoe-20240115143000"
}
```

---

### Option B — AWS Console

1. Sign in to the AWS Console with your IAM user credentials and MFA.
2. Click your account name in the top-right corner and select **Switch Role**.
3. Enter the target **Account ID** and role name `iam-guardrails-breakglass-role`.
4. Optionally provide a display name and colour for easy identification.
5. Click **Switch Role**.

---

### Option C — Automated Script (`breakglass.sh`)

Save the script below, make it executable, and run it. It handles MFA prompting, role assumption, and local audit logging.

<details>
<summary>View breakglass.sh</summary>

```bash
#!/bin/bash
set -euo pipefail

# ── Account Configuration ────────────────────────────────────────────────────
SECURITY_ACCOUNT_ID="865147226759"
DEV_ACCOUNT_ID="418272768233"
MFA_SERIAL="arn:aws:iam::${SECURITY_ACCOUNT_ID}:mfa/${USER}"
ROLE_NAME="iam-guardrails-breakglass-role"

# ── Terminal Colours ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${RED}╔══════════════════════════════════════════╗${NC}"
echo -e "${RED}║   BREAK GLASS ACCESS — EMERGENCY ONLY   ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Confirmation ─────────────────────────────────────────────────────────────
read -rp "Confirm this is a genuine emergency (yes/no): " confirm
[[ "${confirm}" != "yes" ]] && echo "Aborted." && exit 1

read -rp "Enter incident ticket number: " incident_ticket
[[ -z "${incident_ticket}" ]] && echo -e "${RED}Error: Incident ticket is required.${NC}" && exit 1

# ── Account Selection ─────────────────────────────────────────────────────────
echo ""
echo "Select target account:"
echo "  1) Security  (${SECURITY_ACCOUNT_ID})"
echo "  2) Dev       (${DEV_ACCOUNT_ID})"
read -rp "Choice [1/2]: " account_choice
case "${account_choice}" in
  1) TARGET_ACCOUNT_ID="${SECURITY_ACCOUNT_ID}" ;;
  2) TARGET_ACCOUNT_ID="${DEV_ACCOUNT_ID}" ;;
  *) echo "Invalid choice."; exit 1 ;;
esac

# ── MFA Session ───────────────────────────────────────────────────────────────
read -rp "Enter MFA code: " mfa_code
echo -e "${YELLOW}Obtaining MFA session token...${NC}"

aws sts get-session-token \
  --serial-number "${MFA_SERIAL}" \
  --token-code    "${mfa_code}" \
  --duration-seconds 3600 \
  --output json > /tmp/mfa-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/mfa-session.json)

# ── Role Assumption ───────────────────────────────────────────────────────────
echo -e "${YELLOW}Assuming Break Glass role in account ${TARGET_ACCOUNT_ID}...${NC}"
SESSION_NAME="breakglass-${USER}-${incident_ticket}-$(date +%Y%m%d%H%M%S)"
BREAKGLASS_ROLE="arn:aws:iam::${TARGET_ACCOUNT_ID}:role/${ROLE_NAME}"

aws sts assume-role \
  --role-arn          "${BREAKGLASS_ROLE}" \
  --role-session-name "${SESSION_NAME}" \
  --duration-seconds 3600 \
  --output json > /tmp/breakglass-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/breakglass-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/breakglass-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/breakglass-session.json)

# ── Local Audit Log ───────────────────────────────────────────────────────────
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | User: ${USER} | Incident: ${incident_ticket} | Account: ${TARGET_ACCOUNT_ID}" \
  >> ~/.breakglass_audit.log

EXPIRY=$(jq -r '.Credentials.Expiration' /tmp/breakglass-session.json)

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Break Glass Access Granted       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Account : ${TARGET_ACCOUNT_ID}"
echo -e "  Session : ${SESSION_NAME}"
echo -e "  Expires : ${EXPIRY}"
echo ""
echo -e "${RED}  All actions are being logged in CloudTrail.${NC}"
echo -e "${RED}  Exit this session as soon as possible.${NC}"
echo ""

$SHELL
```

</details>

```bash
chmod +x breakglass.sh
./breakglass.sh
```

---

## 5. Step 3 — Perform Emergency Actions

### Rules of Engagement

| Do | Do Not |
|---|---|
| Perform only the minimum actions needed to resolve the incident | Make changes unrelated to the declared emergency |
| Document every action in real time (see log template below) | Share or delegate your Break Glass credentials |
| Verify each command before executing | Leave the session running when unattended |
| Take screenshots or copy output of critical changes | Perform irreversible actions without a second confirmation |
| Exit the session immediately once the issue is resolved | Use the session for routine administrative tasks |

### Real-Time Action Log

Maintain this log throughout the session and attach it to the incident ticket.

| Time (UTC) | IAM Action | Resource | Outcome |
|---|---|---|---|
| `14:32:00` | `iam:CreateAccessKey` | `user/service-account` | Success |
| `14:33:15` | `secretsmanager:UpdateSecret` | `prod/db-credentials` | Success |
| `14:35:00` | `iam:DeleteAccessKey` (old key) | `user/service-account` | Success |

---

## 6. Step 4 — Exit the Break Glass Session

### AWS CLI

```bash
# Unset all temporary credentials
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_PROFILE

# Remove temporary credential files
rm -f /tmp/mfa-session.json /tmp/breakglass-session.json

# Confirm identity has reverted to normal
aws sts get-caller-identity
```

### AWS Console

Click your account name in the top-right corner and select **Switch Back**, or sign out completely.

### Post-Exit Verification

```bash
# This must return AccessDenied to confirm guardrails are active
aws iam create-user --user-name test-blocked-user --profile dev
```

---

## 7. Step 5 — Post-Incident Documentation

Submit an incident report within **24 hours** containing:

- [ ] Incident ticket reference
- [ ] Session start and end time (UTC)
- [ ] Target account(s) accessed
- [ ] Full action log (from Step 3 template above)
- [ ] Root cause of the emergency
- [ ] Any resources created, modified, or deleted
- [ ] Recommended remediation to prevent recurrence

---

## 8. Monitoring and Alerts

Break Glass role activity triggers automatic alerts through two independent mechanisms.

### EventBridge → SNS (Real-Time)

| Event | Rule | Notification |
|---|---|---|
| Role assumption succeeded | `iam-guardrails-breakglass-success` | Immediate SNS email to security team |
| Role assumption failed (API/CLI) | `iam-guardrails-breakglass-failed` | Immediate SNS email |
| Role switch failed (Console) | `iam-guardrails-breakglass-failed-console` | Immediate SNS email |

### CloudTrail Queries

**Query all Break Glass activity in the last 24 hours:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=iam-guardrails-breakglass-role \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time   "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username}' \
  --output table
```

**Query all AssumeRole events referencing the Break Glass role (last 7 days):**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, 'breakglass')]" \
  --output json \
  | jq '.[] | {
      time: .EventTime,
      user: (.CloudTrailEvent | fromjson | .userIdentity.arn),
      sourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)
    }'
```

---

## 9. Cross-Account Access

Use these methods to access the Dev account from the Security account.

### Method 1 — Direct Cross-Account Assume (CLI)

```bash
# ── Authenticate with MFA in the Security account ────────────────────────────
MFA_SERIAL="arn:aws:iam::865147226759:mfa/YOUR_USERNAME"

aws sts get-session-token \
  --serial-number "${MFA_SERIAL}" \
  --token-code    YOUR_MFA_CODE \
  --profile security \
  --output json > /tmp/mfa-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/mfa-session.json)

# ── Assume Security account Break Glass role ──────────────────────────────────
aws sts assume-role \
  --role-arn          arn:aws:iam::865147226759:role/iam-guardrails-breakglass-role \
  --role-session-name breakglass-security \
  --output json > /tmp/security-breakglass.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/security-breakglass.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/security-breakglass.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/security-breakglass.json)

# ── Chain to Dev account Break Glass role ────────────────────────────────────
aws sts assume-role \
  --role-arn          arn:aws:iam::418272768233:role/iam-guardrails-breakglass-role \
  --role-session-name breakglass-dev \
  --output json > /tmp/dev-breakglass.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId'     /tmp/dev-breakglass.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/dev-breakglass.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken'    /tmp/dev-breakglass.json)

aws sts get-caller-identity
```

---

### Method 2 — AWS CLI Named Profiles

Add the following to `~/.aws/config` to enable automatic MFA prompting and role chaining:

```ini
[profile security]
region = us-east-1

[profile security-mfa]
region          = us-east-1
source_profile  = security
mfa_serial      = arn:aws:iam::865147226759:mfa/YOUR_USERNAME

[profile breakglass-security]
region          = us-east-1
source_profile  = security-mfa
role_arn        = arn:aws:iam::865147226759:role/iam-guardrails-breakglass-role

[profile breakglass-dev]
region          = us-east-1
source_profile  = breakglass-security
role_arn        = arn:aws:iam::418272768233:role/iam-guardrails-breakglass-role
```

The AWS CLI will prompt for an MFA code and chain through both roles automatically:

```bash
aws sts get-caller-identity --profile breakglass-dev
```
