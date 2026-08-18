# Incident Response Runbook

**Classification:** Internal — Security Operations
**Owner:** Security Team
**Accounts in Scope:** Security · Dev (see root [README.md](../../README.md) for the account architecture)

> This runbook contains **no credentials, access keys, or secrets** — every command below uses a placeholder in `<ANGLE_BRACKETS>`. Fill placeholders from your own session/ticket; never paste real key material into a ticket, chat, or this file.

---

## Table of Contents

1. [Scenario A — Leaked / Compromised IAM Access Key](#1-scenario-a--leaked--compromised-iam-access-key)
2. [Scenario B — Emergency SCP / Guardrail Bypass](#2-scenario-b--emergency-scp--guardrail-bypass)
3. [Severity & Escalation](#3-severity--escalation)

---

## 1. Scenario A — Leaked / Compromised IAM Access Key

**Trigger examples:** a key committed to a public repo, a Security Hub / GuardDuty finding, an unexpected entry in the Lab 5 "Access Keys > 90 Days Old" panel, or a report from an engineer.

### Step 1 — Contain (stop the bleeding, within minutes)

Deactivate the key immediately. This does not delete it, so it can still be inspected if needed.

```bash
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --user-name <IAM_USER_NAME> \
  --profile <AWS_PROFILE>
```

Confirm no other active key exists for the same user that could be a second leaked credential:

```bash
aws iam list-access-keys \
  --user-name <IAM_USER_NAME> \
  --profile <AWS_PROFILE>
```

### Step 2 — Assess (what did the key do?)

Pull every API call made with the compromised key from CloudTrail:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<ACCESS_KEY_ID> \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time   "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Event:EventName,Resource:Resources}' \
  --output table \
  --profile <AWS_PROFILE>
```

Check specifically for persistence attempts (new identities, new keys, widened permissions, altered trust policies) created by that key in the surrounding time window:

```bash
for EVENT in CreateUser CreateAccessKey CreateLoginProfile AttachUserPolicy \
             PutUserPolicy AttachRolePolicy UpdateAssumeRolePolicy CreateRole; do
  echo "== ${EVENT} =="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="${EVENT}" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --query "Events[?contains(CloudTrailEvent, '<ACCESS_KEY_ID>')]" \
    --output json \
    --profile <AWS_PROFILE>
done
```

> Lab 3's permission boundary limits what a Dev-account key can do even if compromised (no user creation, no destructive actions without MFA, boundary cannot be stripped) — check whether the boundary blocked any of the attempted actions and note that in the ticket.

### Step 3 — Eradicate

Delete the compromised key outright once the investigation above is captured:

```bash
aws iam delete-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --user-name <IAM_USER_NAME> \
  --profile <AWS_PROFILE>
```

Remove anything the attacker planted (only after confirming it is not legitimate infrastructure):

```bash
# Example: remove a rogue access key created during the compromise window
aws iam delete-access-key --access-key-id <ROGUE_KEY_ID> --user-name <ROGUE_USER_NAME> --profile <AWS_PROFILE>

# Example: remove a rogue IAM user created during the compromise window
aws iam delete-user --user-name <ROGUE_USER_NAME> --profile <AWS_PROFILE>
```

If the key was used to assume an IAM role, invalidate every active session on that role by forcing a new minimum credential-issue-time (existing STS sessions immediately fail authorization checks):

```bash
aws iam put-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name ForceCredentialRefresh \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "<REVOCATION_TIMESTAMP_UTC>"}}
    }]
  }' \
  --profile <AWS_PROFILE>
```

### Step 4 — Recover

Issue a replacement key through the existing rotation pipeline (Lab 4) rather than manually, so it lands in Secrets Manager and the rotation clock resets:

```bash
aws lambda invoke \
  --function-name credential-rotator \
  --payload '{"force_user": "<IAM_USER_NAME>"}' \
  --cli-binary-format raw-in-base64-out \
  --profile <AWS_PROFILE> \
  out.json
```

Or manually, if the Lambda path is unavailable:

```bash
aws iam create-access-key --user-name <IAM_USER_NAME> --profile <AWS_PROFILE>
```

### Step 5 — Notify & Document

```bash
aws sns publish \
  --topic-arn <SECURITY_SNS_TOPIC_ARN> \
  --message "Compromised access key ${ACCESS_KEY_ID} for ${IAM_USER_NAME} contained and rotated. See ticket <TICKET_ID>." \
  --profile <AWS_PROFILE>
```

File a post-incident report within 24 hours containing: the CloudTrail activity summary, whether the permission boundary limited impact, any resources created/deleted during eradication, root cause (how the key leaked), and a preventative follow-up (e.g. add a secret-scanning pre-commit hook, shorten the rotation window in Lab 4's `ROTATION_AGE_DAYS`).

---

## 2. Scenario B — Emergency SCP / Guardrail Bypass

Preventative guardrails (permission boundary, SCPs, Config rules from Lab 3) are expected to block most actions by design. This section is for the rare case where a **legitimate emergency action is blocked and must proceed immediately**.

### Step 1 — Use the existing Break Glass path first

The tagged Break Glass role is the sanctioned bypass for account-level guardrails (permission boundary Deny statements) and is fully documented, alerted, and audited already: see [Lab3/docs/breakglass-procedure.md](../../Lab3/docs/breakglass-procedure.md). In the overwhelming majority of cases this is the only step needed — assume the role, perform the minimum action required, exit, and file the post-incident report as described there.

### Step 2 — Organization-level SCP detachment (last resort only)

Use this **only** if an AWS Organizations SCP — not the account permission boundary — is blocking the Break Glass role itself, and the emergency cannot wait for a change through normal Organizations administration.

**Required before proceeding:**
- [ ] Incident ticket open
- [ ] A second approver (security lead or manager) has signed off — verbally is acceptable if written approval isn't possible in time, but must be documented immediately after
- [ ] A specific re-attach time is agreed upon (time-boxed, not indefinite)

```bash
# Identify the SCP and what it's attached to
aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --profile <ORG_MANAGEMENT_PROFILE>

aws organizations list-targets-for-policy \
  --policy-id <POLICY_ID> \
  --profile <ORG_MANAGEMENT_PROFILE>

# Detach the SCP from the affected account
aws organizations detach-policy \
  --policy-id <POLICY_ID> \
  --target-id <ACCOUNT_ID> \
  --profile <ORG_MANAGEMENT_PROFILE>
```

Perform only the minimum action required to resolve the emergency, logging every command and timestamp in the Break Glass action log (same template as [Lab3/docs/breakglass-procedure.md](../../Lab3/docs/breakglass-procedure.md#5-step-3--perform-emergency-actions)).

**Re-attach immediately once the emergency action is complete:**

```bash
aws organizations attach-policy \
  --policy-id <POLICY_ID> \
  --target-id <ACCOUNT_ID> \
  --profile <ORG_MANAGEMENT_PROFILE>
```

Verify the guardrail is active again by re-running the Lab 3 Config compliance check for the affected account, and confirm a blocked action correctly returns `AccessDenied`:

```bash
aws configservice describe-compliance-by-config-rule \
  --config-rule-names iam-guardrails-permission-boundary-check \
  --profile <AWS_PROFILE>
```

### Step 3 — Post-Incident (mandatory, within 24 hours)

- [ ] Confirm the SCP was re-attached (Step 2 verification above)
- [ ] File the same post-incident report template as the Break Glass procedure: ticket, session times, actions taken, business justification, and a recommendation to prevent recurrence without a bypass next time

---

## 3. Severity & Escalation

| Signal | Suggested Severity | First Action |
|---|---|---|
| Single stale/unused key flagged by Lab 5 dashboard, no CloudTrail activity from it | Low | Deactivate and rotate on next scheduled pass |
| Active key used from an unrecognized source IP / region | High | Start Scenario A immediately |
| Evidence of persistence (new user/role/key created by the leaked credential) | Critical | Start Scenario A, notify security lead in parallel, do not wait for approval to contain |
| A genuine operational emergency blocked by an SCP and Break Glass is insufficient | High | Start Scenario B, Step 1 first — escalate to Step 2 only if that fails |
