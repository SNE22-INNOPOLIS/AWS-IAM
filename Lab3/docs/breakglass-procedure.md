# Break Glass Procedure

## Overview

The Break Glass procedure provides emergency access to bypass guardrails when necessary. This should only be used in genuine emergencies when normal access is insufficient.

## Prerequisites

1. MFA device configured for the user
2. User is authorized for Break Glass access
3. Incident ticket or documented emergency

## Procedure

### Step 1: Document the Emergency

Before using Break Glass access:
- Create an incident ticket
- Document the reason for emergency access
- Get approval from security team (if time permits)
- Note the start time

### Step 2: Assume the Break Glass Role

#### Option A: AWS CLI

```bash
# Replace with your actual values
MFA_SERIAL="arn:aws:iam::ACCOUNT_ID:mfa/YOUR_USERNAME"
MFA_CODE="123456"  # Your current MFA code

# Get session token with MFA
aws sts get-session-token \
  --serial-number ${MFA_SERIAL} \
  --token-code ${MFA_CODE} \
  --duration-seconds 3600 \
  --profile your-profile \
  --output json > /tmp/mfa-session.json

# Export the temporary credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/mfa-session.json)

# Replace ACCOUNT_ID with target account
BREAKGLASS_ROLE="arn:aws:iam::ACCOUNT_ID:role/iam-guardrails-breakglass-role"
SESSION_NAME="breakglass-$(whoami)-$(date +%Y%m%d%H%M%S)"

# Assume the Break Glass role
aws sts assume-role \
  --role-arn ${BREAKGLASS_ROLE} \
  --role-session-name ${SESSION_NAME} \
  --duration-seconds 3600 \
  --output json > /tmp/breakglass-session.json

# Export the Break Glass credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/breakglass-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/breakglass-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/breakglass-session.json)

# Verify you have Break Glass access
aws sts get-caller-identity
```

Expected Output:

```bash
{
    "UserId": "AROA...:breakglass-johndoe-20240115143000",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/iam-guardrails-breakglass-role/breakglass-johndoe-20240115143000"
}
```

#### Option B: AWS Console

1. Sign in to AWS Console with MFA
2. Navigate to IAM → Roles
3. Search for `iam-guardrails-breakglass-role`
4. Click Switch Role or use the role switcher in the top navigation
5. Enter the account ID and role name

#### Option C: Using a Break Glass Script

Save this as `breakglass.sh`:

<details>
<summary>breakglass.sh</summary>

```bash
#!/bin/bash
set -e

# Configuration
SECURITY_ACCOUNT_ID="111111111111"
DEV_ACCOUNT_ID="222222222222"
MFA_SERIAL="arn:aws:iam::${SECURITY_ACCOUNT_ID}:mfa/${USER}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}========================================${NC}"
echo -e "${RED}  BREAK GLASS ACCESS - EMERGENCY ONLY  ${NC}"
echo -e "${RED}========================================${NC}"
echo ""

# Prompt for confirmation
read -p "Are you sure you need Break Glass access? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

# Prompt for incident ticket
read -p "Enter incident ticket number: " incident_ticket
if [ -z "$incident_ticket" ]; then
    echo -e "${RED}Error: Incident ticket is required${NC}"
    exit 1
fi

# Select target account
echo ""
echo "Select target account:"
echo "1) Security Account (${SECURITY_ACCOUNT_ID})"
echo "2) Dev Account (${DEV_ACCOUNT_ID})"
read -p "Enter choice (1 or 2): " account_choice

case $account_choice in
    1) TARGET_ACCOUNT_ID=$SECURITY_ACCOUNT_ID ;;
    2) TARGET_ACCOUNT_ID=$DEV_ACCOUNT_ID ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

# Get MFA code
read -p "Enter MFA code: " mfa_code

echo -e "${YELLOW}Getting MFA session...${NC}"

# Get MFA session
aws sts get-session-token \
  --serial-number ${MFA_SERIAL} \
  --token-code ${mfa_code} \
  --duration-seconds 3600 \
  --output json > /tmp/mfa-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/mfa-session.json)

echo -e "${YELLOW}Assuming Break Glass role...${NC}"

# Assume Break Glass role
SESSION_NAME="breakglass-${USER}-${incident_ticket}-$(date +%Y%m%d%H%M%S)"
BREAKGLASS_ROLE="arn:aws:iam::${TARGET_ACCOUNT_ID}:role/iam-guardrails-breakglass-role"

aws sts assume-role \
  --role-arn ${BREAKGLASS_ROLE} \
  --role-session-name ${SESSION_NAME} \
  --duration-seconds 3600 \
  --output json > /tmp/breakglass-session.json

export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/breakglass-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/breakglass-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/breakglass-session.json)

# Log the access
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | User: ${USER} | Incident: ${incident_ticket} | Account: ${TARGET_ACCOUNT_ID}" >> ~/.breakglass_audit.log

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Break Glass Access Granted${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Account: ${TARGET_ACCOUNT_ID}"
echo -e "Session: ${SESSION_NAME}"
echo -e "Expires: $(jq -r '.Credentials.Expiration' /tmp/breakglass-session.json)"
echo ""
echo -e "${RED}REMINDER: All actions are being logged!${NC}"
echo -e "${RED}Exit this session as soon as possible.${NC}"
echo ""

# Start a new shell with the credentials
$SHELL
```
</details>

Usage:

```bash
chmod +x breakglass.sh
./breakglass.sh
```

### Step 3: Perform Emergency Actions

While using Break Glass access:

DO:

✅ Perform only the necessary actions to resolve the emergency
✅ Document every action you take in real-time
✅ Keep your session as short as possible
✅ Verify each action before executing
✅ Take screenshots of critical changes

DON'T:

❌ Make unnecessary changes
❌ Explore or browse resources unrelated to the emergency
❌ Share credentials with others
❌ Leave the session unattended
❌ Perform destructive actions without double-checking

Action Log Template:

Time (UTC)    | Action                           | Resource              | Result
--------------|----------------------------------|----------------------|--------
14:32:00      | iam:CreateAccessKey              | user/service-account | Success
14:33:15      | secretsmanager:UpdateSecret      | prod/db-credentials  | Success
14:35:00      | iam:DeleteAccessKey (old key)    | user/service-account | Success

### Step 4: Exit Break Glass Session

```bash
# Clear all AWS environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_PROFILE

# Remove temporary credential files
rm -f /tmp/mfa-session.json
rm -f /tmp/breakglass-session.json

# Verify credentials are cleared
aws sts get-caller-identity
# Should fail or show your normal identity
```
In Console: Click your username → Switch Back or sign out completely.

Verification:

```bash
# Confirm you no longer have Break Glass access
aws iam create-user --user-name test-verification-user
# Should fail with AccessDenied if guardrails are working
```

### Step 5: Post-Incident Documentation

Complete the incident report with:

- Start and end time of Break Glass session
- All actions performed
- Reason for each action
- Any changes made to resources
- Recommendations to prevent future emergencies



## Monitoring & Alerts

Break Glass role usage is automatically monitored:

1. CloudWatch Alarm: Triggers when the role is assumed
    - Alarm Name: `iam-guardrails-breakglass-usage-alarm`
    - Metric: `BreakGlassRoleUsage`
    - Threshold: Any usage (> 0)
    - Notification: SNS topic `iam-guardrails-alerts`
2. CloudTrail Logs: All actions performed with the Break Glass role are logged

```bash
# Query CloudTrail for Break Glass activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=iam-guardrails-breakglass-role \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username}' \
  --output table
```
View Recent Break Glass Activity

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query "Events[?contains(CloudTrailEvent, 'breakglass')]" \
  --output json | jq '.[] | {time: .EventTime, event: .CloudTrailEvent | fromjson | {user: .userIdentity.arn, sourceIP: .sourceIPAddress}}'
```

3. SNS Notification: Security team is notified immediately


## Cross-Account Break Glass Access

To access the Dev account from the Security account:

### Method 1: Direct Cross-Account Assume

```bash
# First, authenticate with MFA in Security account
MFA_SERIAL="arn:aws:iam::SECURITY_ACCOUNT_ID:mfa/YOUR_USERNAME"

aws sts get-session-token \
  --serial-number ${MFA_SERIAL} \
  --token-code YOUR_MFA_CODE \
  --profile security \
  --output json > /tmp/mfa-session.json

# Export MFA session credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/mfa-session.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/mfa-session.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/mfa-session.json)

# Assume Security account Break Glass role
aws sts assume-role \
  --role-arn arn:aws:iam::SECURITY_ACCOUNT_ID:role/iam-guardrails-breakglass-role \
  --role-session-name breakglass-step1 \
  --output json > /tmp/security-breakglass.json

# Export Security Break Glass credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/security-breakglass.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/security-breakglass.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/security-breakglass.json)

# Now assume Dev account Break Glass role
aws sts assume-role \
  --role-arn arn:aws:iam::DEV_ACCOUNT_ID:role/iam-guardrails-breakglass-role \
  --role-session-name breakglass-dev-access \
  --output json > /tmp/dev-breakglass.json

# Export Dev Break Glass credentials
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/dev-breakglass.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/dev-breakglass.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/dev-breakglass.json)

# Verify
aws sts get-caller-identity
```

## Method 2: Using AWS CLI Profiles

Add to `~/.aws/config`:

```bash
[profile security]
region = us-east-1

[profile security-mfa]
region = us-east-1
source_profile = security
mfa_serial = arn:aws:iam::SECURITY_ACCOUNT_ID:mfa/YOUR_USERNAME

[profile breakglass-security]
region = us-east-1
source_profile = security-mfa
role_arn = arn:aws:iam::SECURITY_ACCOUNT_ID:role/iam-guardrails-breakglass-role

[profile breakglass-dev]
region = us-east-1
source_profile = breakglass-security
role_arn = arn:aws:iam::DEV_ACCOUNT_ID:role/iam-guardrails-breakglass-role
```

Usage:

```bash
# Will prompt for MFA and chain through roles
aws sts get-caller-identity --profile breakglass-dev
```