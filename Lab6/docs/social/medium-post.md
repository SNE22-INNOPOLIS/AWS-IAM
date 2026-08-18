# Draft — Medium Post

**Working title:** "Six Labs, One AWS Org: Building a Preventative IAM Security Program from Scratch"

**Status:** Draft — review and add a personal byline/handle before publishing externally.

---

Most IAM write-ups stop at "here's an audit script." Over six labs, this project went further: detect (Access Analyzer, unused-permission reports), prevent (permission boundaries, SCP-style guardrails, an auto-remediation Lambda), respond (automated key rotation, a Break Glass role with real-time SNS alerts), and finally, report (a QuickSight dashboard turning findings into three metrics leadership can actually read).

**What it covers:**

- A two-account (Security/Dev) foundation with centralized CloudTrail and Config logging
- IAM Access Analyzer plus a scheduled audit Lambda that flags permissions unused for 90+ days
- A permission boundary and Config rules that block risky IAM actions without MFA — auto-attached to every new principal within seconds
- A weekly Lambda that rotates access keys older than 90 days into Secrets Manager, with pre/post SNS notice
- An IAM Health dashboard in QuickSight built on Security Hub + CloudTrail + Athena
- An architecture diagram and incident response runbook tying it all together (this lab)

**Why it matters:** most IAM security work is either all-audit (reports nobody reads) or all-prevention (breaks legitimate workflows with no escape hatch). This project's Break Glass pattern — a tagged role that bypasses guardrails only under MFA, with mandatory logging and real-time alerting — is the piece that makes strict guardrails survivable in practice.

Full source, including every Terraform module and Lambda: link to the repository.

*(Fill in publication specifics — canonical link, tags, cover image — before posting.)*
