# Dashboard Screenshots

Place screenshots here after the first QuickSight dashboard deployment.

## Expected Visuals

### 1 — IAM Health Overview sheet

Three visuals on a single QuickSight sheet:

```
┌──────────────────────────────┬──────────────────────────────┐
│  % Roles with Unused         │  Access Keys > 90 Days Old   │
│  Permissions                 │                              │
│                              │                              │
│        72.4%                 │            5                 │
│   ▲ +3.1% vs yesterday       │   ▼ -1 vs yesterday          │
└──────────────────────────────┴──────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│  SCP Violation Attempts — Last 30 Days                       │
│                                                              │
│   12 ┤                          ╭──╮                         │
│    9 ┤              ╭──╮       ╭╯  ╰──╮                     │
│    6 ┤    ╭──╮     ╭╯  ╰──────╯      ╰──                    │
│    3 ┤────╯  ╰─────╯                                        │
│    0 └──────────────────────────────────────────────────────│
│      Jun 8       Jun 15       Jun 22       Jun 29           │
└──────────────────────────────────────────────────────────────┘
```

### Naming Convention for Screenshots

| Filename | Contents |
|---|---|
| `01_iam_health_overview.png` | Full dashboard sheet |
| `02_kpi_unused_permissions.png` | % Roles with Unused Permissions KPI |
| `03_kpi_stale_keys.png` | Access Keys > 90 Days KPI |
| `04_scp_violations_trend.png` | SCP violation line chart |
| `05_quicksight_dataset_config.png` | Dataset configuration showing Athena connection |

## Capture Instructions

1. Open the QuickSight dashboard URL from `terraform output quicksight_dashboard_url`
2. Set the date filter to **Last 30 days**
3. Use browser full-page screenshot (e.g., Firefox → More tools → Take screenshot → Save full page)
4. Crop each individual visual separately for the individual files above
5. Commit screenshots: `git add docs/dashboard/*.png && git commit -m "lab5: add dashboard screenshots"`
