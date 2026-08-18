# Draft — LinkedIn Post

**Status:** Draft — add a personal note and the repo link before posting.

---

Just wrapped up a 6-lab AWS IAM security portfolio, built entirely in Terraform across a two-account org:

🔎 Detect — IAM Access Analyzer + a scheduled audit Lambda flagging permissions unused for 90+ days
🛡️ Prevent — a permission boundary + guardrail Lambda that auto-attaches to every new IAM principal and blocks destructive actions without MFA
🔁 Respond — automated weekly access-key rotation into Secrets Manager, and a Break Glass role for genuine emergencies (MFA-gated, fully alerted via SNS)
📊 Report — a QuickSight dashboard surfacing IAM health metrics from Security Hub and CloudTrail via Athena
📄 Document — an architecture diagram and an incident response runbook with copy-pasteable CLI commands for a leaked-key scenario and an emergency guardrail bypass

The biggest lesson: guardrails only survive contact with real operations if there's a documented, audited escape hatch. Break Glass access with mandatory MFA + real-time alerting made it possible to keep the preventative controls strict everywhere else.

#AWS #IAM #CloudSecurity #Terraform #SecurityEngineering

*(Add repo link before publishing.)*
