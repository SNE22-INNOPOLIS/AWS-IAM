"""Regenerates /docs/architecture.png from the box/arrow layout below."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D

OUTPUT_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "architecture.png")
)

fig, ax = plt.subplots(figsize=(19, 12.5), dpi=160)
ax.set_xlim(0, 19)
ax.set_ylim(0, 12.5)
ax.axis("off")

COL_DEV = "#e8f0fe"
COL_DEV_EDGE = "#2f5fbf"
COL_SEC = "#fdeee8"
COL_SEC_EDGE = "#c04a1e"
COL_SHARED = "#eef3ea"
COL_SHARED_EDGE = "#4a7a3c"
TEXT_DARK = "#1b1b1b"


def box(x, y, w, h, text, edge, fill, fontsize=10.3, weight="normal"):
    b = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=1.6, edgecolor=edge, facecolor=fill, zorder=3,
    )
    ax.add_patch(b)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
             fontsize=fontsize, color=TEXT_DARK, weight=weight, zorder=4,
             linespacing=1.35)
    return (x, y, w, h)


def anchor(b, side):
    x, y, w, h = b
    return {
        "top": (x + w / 2, y + h),
        "bottom": (x + w / 2, y),
        "left": (x, y + h / 2),
        "right": (x + w, y + h / 2),
    }[side]


def arrow(p1, p2, color="#333333", style="-|>", lw=1.6, ls="solid",
          label=None, label_pos=0.5, connection="arc3,rad=0.0", fontsize=8.6):
    a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=14,
                         color=color, linewidth=lw, linestyle=ls,
                         connectionstyle=connection, zorder=2)
    ax.add_patch(a)
    if label:
        mx = p1[0] + (p2[0] - p1[0]) * label_pos
        my = p1[1] + (p2[1] - p1[1]) * label_pos
        ax.text(mx, my, label, ha="center", va="center", fontsize=fontsize,
                 color=color, zorder=5,
                 bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.85))


# ---------------------------------------------------------------- Title
ax.text(9.5, 12.1, "AWS IAM Security Portfolio — Cross-Account Architecture & Data Flow",
        ha="center", va="center", fontsize=16, weight="bold", color=TEXT_DARK)
ax.text(9.5, 11.65, "Two-account model — Security (control plane) and Dev (workload / guardrailed) — Labs 1-5",
        ha="center", va="center", fontsize=10.5, color="#555555")

# ---------------------------------------------------------------- Account containers
dev_container = FancyBboxPatch((0.4, 0.6), 6.6, 10.5, boxstyle="round,pad=0.02,rounding_size=0.12",
                                linewidth=2.2, edgecolor=COL_DEV_EDGE, facecolor="#f5f8ff", zorder=1)
ax.add_patch(dev_container)
ax.text(3.7, 10.75, "DEV ACCOUNT", ha="center", fontsize=13, weight="bold", color=COL_DEV_EDGE)
ax.text(3.7, 10.4, "workload account · guardrails enforced", ha="center", fontsize=9, color="#3d5a8a")

sec_container = FancyBboxPatch((7.6, 0.6), 11.0, 10.5, boxstyle="round,pad=0.02,rounding_size=0.12",
                                linewidth=2.2, edgecolor=COL_SEC_EDGE, facecolor="#fff6f2", zorder=1)
ax.add_patch(sec_container)
ax.text(13.1, 10.75, "SECURITY ACCOUNT", ha="center", fontsize=13, weight="bold", color=COL_SEC_EDGE)
ax.text(13.1, 10.4, "central logging · audit · guardrail automation · reporting", ha="center", fontsize=9, color="#8a3d20")

# ---------------------------------------------------------------- Dev account nodes
d_users = box(0.9, 8.8, 5.7, 0.95, "IAM Users, Roles & Access Keys\n(Dev workloads)", COL_DEV_EDGE, COL_DEV)
d_boundary = box(0.9, 7.35, 5.7, 1.15,
                  "Permission Boundary + Guardrail Lambda\n+ AWS Config Rules  —  Lab 3\nDeny risky actions without MFA · auto-attach boundary",
                  COL_DEV_EDGE, COL_DEV, fontsize=9.6)
d_analyzer = box(0.9, 5.95, 5.7, 0.95, "IAM Access Analyzer  —  Lab 2\nExternal-access findings", COL_DEV_EDGE, COL_DEV)
d_trail = box(0.9, 4.6, 5.7, 0.95, "CloudTrail + AWS Config Recorder  —  Lab 1\nMulti-region audit trail", COL_DEV_EDGE, COL_DEV)
d_bg = box(0.9, 3.25, 5.7, 0.95, "Break Glass Role (Dev)  —  Lab 3\ntag: Purpose=BreakGlass", COL_DEV_EDGE, "#fdf3e3")

ax.text(3.7, 1.9, "Every destructive/high-risk action is denied unless the\ncaller assumes the tagged Break Glass role (MFA-gated).",
        ha="center", fontsize=8.6, color="#7a5a1e", style="italic")

# ---------------------------------------------------------------- Security account nodes (left sub-column: ingestion)
s_hub = box(8.0, 8.8, 5.0, 0.95, "Security Hub + IAM Audit Lambda  —  Lab 2\nAggregated findings · unused-permission report", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_logbucket = box(8.0, 7.35, 5.0, 0.95, "Central Log Bucket  —  Lab 1\nCloudTrail + Config from both accounts", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_rotator = box(8.0, 5.95, 5.0, 0.95, "Credential Rotator Lambda  —  Lab 4\nEventBridge rate(7 days) · rotates keys > 90d", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_secrets = box(8.0, 4.6, 2.35, 0.95, "Secrets Manager\niam/access-keys/<user>", COL_SEC_EDGE, COL_SEC, fontsize=8.8)
s_sns_rotate = box(10.65, 4.6, 2.35, 0.95, "SNS Topic\npre/post-rotation email", COL_SEC_EDGE, COL_SEC, fontsize=8.8)
s_bg = box(8.0, 3.25, 5.0, 0.95, "Break Glass Role (Security)  —  Lab 3\n+ SNS alert on every assume attempt", COL_SEC_EDGE, "#fdf3e3", fontsize=9.3)

# ---------------------------------------------------------------- Security account nodes (right sub-column: dashboard pipeline, Lab 5)
s_agg = box(13.4, 8.8, 4.9, 0.95, "IAM Findings Aggregator Lambda  —  Lab 5\nEventBridge daily 01:00 UTC", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_s3 = box(13.4, 7.35, 4.9, 0.95, "S3 — NDJSON findings\nyear=/month=/day= partitions", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_glue = box(13.4, 5.95, 4.9, 0.95, "Glue Crawler (daily 02:00 UTC)\n→ iam_health_db  →  Athena Workgroup", COL_SEC_EDGE, COL_SEC, fontsize=9.3)
s_qs = box(13.4, 4.6, 4.9, 0.95, "QuickSight Dashboard  —  Lab 5\n\"IAM Health Overview\"", COL_SEC_EDGE, COL_SEC, fontsize=9.6)

# ---------------------------------------------------------------- Shared foundation (bottom strip)
shared = box(0.9, 1.55, 17.4, 0.85,
             "Shared Terraform Backend — Lab 1 bootstrap:  S3 state bucket + DynamoDB lock table  (used by every lab's Terraform workspace)",
             COL_SHARED_EDGE, COL_SHARED, fontsize=10)

# ---------------------------------------------------------------- Arrows: Dev -> Security (data flow)
arrow(anchor(d_trail, "right"), anchor(s_logbucket, "left"), color=COL_DEV_EDGE,
      label="log delivery", connection="arc3,rad=0.12", label_pos=0.5, fontsize=8.4)
arrow(anchor(d_analyzer, "right"), anchor(s_hub, "left"), color=COL_DEV_EDGE,
      label="findings", connection="arc3,rad=0.12", label_pos=0.5, fontsize=8.4)

# Break glass cross-account (dashed, bidirectional)
arrow(anchor(d_bg, "right"), anchor(s_bg, "left"), color="#8a5a1e", ls="dashed", style="<|-|>",
      label="cross-account assume (MFA required)", connection="arc3,rad=-0.05", fontsize=8.3)

# ---------------------------------------------------------------- Arrows: within Security (ingestion column)
arrow(anchor(s_rotator, "bottom"), anchor(s_secrets, "top"), color=COL_SEC_EDGE, connection="arc3,rad=0.0")
arrow(anchor(s_rotator, "bottom"), anchor(s_sns_rotate, "top"), color=COL_SEC_EDGE, connection="arc3,rad=0.0")

# ---------------------------------------------------------------- Arrows: ingestion -> aggregator pipeline (Lab 5 pulls from Lab 1/2)
arrow(anchor(s_hub, "right"), anchor(s_agg, "left"), color=COL_SEC_EDGE,
      label="Security Hub findings", connection="arc3,rad=0.0", fontsize=8.2, label_pos=0.5)
arrow(anchor(s_logbucket, "right"), anchor(s_agg, "bottom"), color=COL_SEC_EDGE,
      label="CloudTrail AccessDenied (SCP)\n+ IAM last-accessed data", connection="arc3,rad=-0.25", fontsize=7.9, label_pos=0.28)

# Aggregator pipeline chain
arrow(anchor(s_agg, "bottom"), anchor(s_s3, "top"), color=COL_SEC_EDGE)
arrow(anchor(s_s3, "bottom"), anchor(s_glue, "top"), color=COL_SEC_EDGE)
arrow(anchor(s_glue, "bottom"), anchor(s_qs, "top"), color=COL_SEC_EDGE)

# ---------------------------------------------------------------- Legend
legend_elems = [
    Line2D([0], [0], marker="s", color="none", markerfacecolor=COL_DEV, markeredgecolor=COL_DEV_EDGE, markersize=14, label="Dev account resource"),
    Line2D([0], [0], marker="s", color="none", markerfacecolor=COL_SEC, markeredgecolor=COL_SEC_EDGE, markersize=14, label="Security account resource"),
    Line2D([0], [0], marker="s", color="none", markerfacecolor=COL_SHARED, markeredgecolor=COL_SHARED_EDGE, markersize=14, label="Shared foundation (Lab 1)"),
    Line2D([0], [0], color="#8a5a1e", lw=1.6, ls="dashed", label="Emergency / Break Glass path (MFA-gated)"),
]
ax.legend(handles=legend_elems, loc="lower center", bbox_to_anchor=(0.5, -0.045),
          ncol=4, frameon=False, fontsize=9.2)

ax.text(9.5, 0.75, "No account IDs, access keys, or secrets are rendered above — see Lab6/docs/incident-response-runbook.md for operational detail.",
        ha="center", fontsize=8.3, color="#777777", style="italic")

plt.tight_layout()
plt.savefig(OUTPUT_PATH, dpi=160, bbox_inches="tight", facecolor="white")
print(f"saved {OUTPUT_PATH}")
