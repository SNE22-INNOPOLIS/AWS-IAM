# Lab 6 — Architecture Diagram & Operational Runbook

A project without documentation is a hobby, not engineering. This lab produces the operational documentation that turns Labs 1–5 into something a second engineer (or on-call responder) could pick up cold: a single architecture diagram of the whole portfolio, and an incident response runbook with copy-pasteable CLI commands for the two scenarios that actually page someone — a leaked access key, and a guardrail that needs an emergency, time-boxed bypass.

This lab ships **no Terraform and no AWS resources** — it is documentation only.

---

## Overview

| Deliverable | Location |
|---|---|
| Architecture diagram (whole-portfolio data flow) | [docs/architecture.png](../docs/architecture.png) |
| Incident response runbook (leaked key + emergency SCP bypass) | [docs/incident-response-runbook.md](docs/incident-response-runbook.md) |
| Diagram source (regenerate on architecture changes) | [scripts/generate_architecture_diagram.py](scripts/generate_architecture_diagram.py) |
| Social write-ups (Medium / LinkedIn) | [docs/social/](docs/social/) |

The diagram shows the two-account model (Security / Dev) and how data flows between every prior lab: CloudTrail/Config log delivery (Lab 1), Access Analyzer and audit findings (Lab 2), the permission boundary and Break Glass role (Lab 3), the credential rotation pipeline (Lab 4), and the findings-aggregation pipeline feeding the QuickSight dashboard (Lab 5).

The runbook is deliberately scoped to the two incident types the guardrails in this repo are built around: a compromised IAM access key, and a legitimate emergency that a permission boundary or SCP is blocking. For the day-to-day Break Glass procedure (routine emergency admin access), the canonical source of truth remains [Lab3/docs/breakglass-procedure.md](../Lab3/docs/breakglass-procedure.md) — this lab's runbook cross-references it rather than duplicating it.

---

## Prerequisites

Since this lab has no infrastructure, there are no AWS prerequisites to *use* the documentation. Regenerating the diagram (only needed if the architecture changes) requires:

- Python >= 3.10
- `matplotlib` (`pip install matplotlib`)

No AWS credentials, IAM permissions, or Terraform state are required for anything in this lab.

---

## Deployment

There is nothing to `terraform apply` — "deployment" here means publishing/updating the docs.

### Regenerate the architecture diagram (only after changing the architecture)

```bash
cd Lab6/scripts
pip install matplotlib
python generate_architecture_diagram.py
```

This overwrites [`/docs/architecture.png`](../docs/architecture.png) at the repository root in place.

### Update the runbook

Edit [docs/incident-response-runbook.md](docs/incident-response-runbook.md) directly. Before committing, re-check that every command still uses a `<PLACEHOLDER>` — never a real account ID, key ID, or ARN copied from a live session.

---

## Module Structure

```
Lab6/
├── README.md
├── docs/
│   ├── incident-response-runbook.md   ← leaked key + emergency SCP bypass, with CLI commands
│   └── social/
│       ├── medium-post.md
│       └── linkedin-post.md
└── scripts/
    └── generate_architecture_diagram.py   ← regenerates /docs/architecture.png

docs/
└── architecture.png                        ← whole-portfolio architecture diagram (acceptance criterion path)
```

---

## Cost Estimate

**$0.00.** This lab provisions zero AWS resources — no Lambda, no S3, no EventBridge, nothing billable. It is Markdown and a PNG committed to the repository.

| Resource | Monthly Cost |
|---|---|
| Everything in this lab | $0.00 |

---

## Cleanup

Nothing to tear down — there is no Terraform state, no deployed infrastructure, and no `terraform destroy` for this lab. Deleting the `Lab6/` folder and `docs/architecture.png` fully removes every artifact this lab created.
