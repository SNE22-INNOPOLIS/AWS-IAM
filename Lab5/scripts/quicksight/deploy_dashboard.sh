#!/usr/bin/env bash
# =============================================================================
# Lab 5 — Deploy IAM Health QuickSight Dashboard
#
# Prerequisites:
#   1. terraform apply has completed successfully
#   2. The Glue Crawler has run at least once (tables exist in Athena)
#   3. AWS CLI profile has QuickSight permissions
#   4. QuickSight is subscribed in this account
#
# Usage:
#   cd Lab5/scripts/quicksight
#   bash deploy_dashboard.sh [--profile security] [--region us-east-1]
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults — override via CLI flags or environment variables
# ---------------------------------------------------------------------------
PROFILE="${AWS_PROFILE:-security}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
DASHBOARD_ID="iam-health-dashboard"
DASHBOARD_NAME="IAM Health Overview"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFINITION_FILE="${SCRIPT_DIR}/dashboard_definition.json"
TF_DIR="${SCRIPT_DIR}/../../terraform"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)  PROFILE="$2";  shift 2 ;;
    --region)   REGION="$2";   shift 2 ;;
    --dashboard-id) DASHBOARD_ID="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

echo "==> Using profile: ${PROFILE}  region: ${REGION}"

# ---------------------------------------------------------------------------
# Read Terraform outputs
# ---------------------------------------------------------------------------
echo "==> Reading Terraform outputs from ${TF_DIR}"
cd "${TF_DIR}"
TF_JSON=$(terraform output -json 2>/dev/null)

ACCOUNT_ID=$(echo "${TF_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['account_id']['value'])")
UNUSED_DS_ARN=$(echo "${TF_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['quicksight_unused_permissions_dataset_arn']['value'])")
STALE_DS_ARN=$(echo "${TF_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['quicksight_stale_keys_dataset_arn']['value'])")
SCP_DS_ARN=$(echo "${TF_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['quicksight_scp_violations_dataset_arn']['value'])")
QS_USER_ARN=$(echo "${TF_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['quicksight_user_arn']['value'])")

echo "    Account ID:          ${ACCOUNT_ID}"
echo "    Unused Perms DS ARN: ${UNUSED_DS_ARN}"
echo "    Stale Keys DS ARN:   ${STALE_DS_ARN}"
echo "    SCP Violations ARN:  ${SCP_DS_ARN}"
echo "    QuickSight User ARN: ${QS_USER_ARN}"

# ---------------------------------------------------------------------------
# Patch the dashboard definition with real dataset ARNs
# ---------------------------------------------------------------------------
echo "==> Patching dashboard definition"
PATCHED_DEFINITION=$(
  sed \
    -e "s|__UNUSED_PERMISSIONS_DATASET_ARN__|${UNUSED_DS_ARN}|g" \
    -e "s|__STALE_ACCESS_KEYS_DATASET_ARN__|${STALE_DS_ARN}|g"    \
    -e "s|__SCP_VIOLATIONS_DATASET_ARN__|${SCP_DS_ARN}|g"         \
    "${DEFINITION_FILE}"
)

# ---------------------------------------------------------------------------
# Check if dashboard already exists (update vs create)
# ---------------------------------------------------------------------------
EXISTS=$(
  aws quicksight describe-dashboard \
    --aws-account-id "${ACCOUNT_ID}" \
    --dashboard-id   "${DASHBOARD_ID}" \
    --profile        "${PROFILE}" \
    --region         "${REGION}" \
    --query          'Dashboard.DashboardId' \
    --output         text \
    2>/dev/null || echo "NOT_FOUND"
)

PERMISSIONS_JSON="[{\"Principal\":\"${QS_USER_ARN}\",\"Actions\":[\"quicksight:DescribeDashboard\",\"quicksight:ListDashboardVersions\",\"quicksight:UpdateDashboardPermissions\",\"quicksight:QueryDashboard\",\"quicksight:UpdateDashboard\",\"quicksight:DeleteDashboard\",\"quicksight:DescribeDashboardPermissions\",\"quicksight:UpdateDashboardPublishedVersion\"]}]"

if [[ "${EXISTS}" == "NOT_FOUND" ]]; then
  echo "==> Creating dashboard: ${DASHBOARD_ID}"
  RESPONSE=$(
    aws quicksight create-dashboard \
      --aws-account-id "${ACCOUNT_ID}" \
      --dashboard-id   "${DASHBOARD_ID}" \
      --name           "${DASHBOARD_NAME}" \
      --definition     "${PATCHED_DEFINITION}" \
      --permissions    "${PERMISSIONS_JSON}" \
      --dashboard-publish-options \
        "AdHocFilteringOption={AvailabilityStatus=ENABLED},ExportToCSVOption={AvailabilityStatus=ENABLED},SheetControlsOption={VisibilityState=EXPANDED}" \
      --profile "${PROFILE}" \
      --region  "${REGION}" \
      --output  json
  )
else
  echo "==> Updating existing dashboard: ${DASHBOARD_ID}"
  RESPONSE=$(
    aws quicksight update-dashboard \
      --aws-account-id "${ACCOUNT_ID}" \
      --dashboard-id   "${DASHBOARD_ID}" \
      --name           "${DASHBOARD_NAME}" \
      --definition     "${PATCHED_DEFINITION}" \
      --profile "${PROFILE}" \
      --region  "${REGION}" \
      --output  json
  )
fi

echo "${RESPONSE}" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Status:', d.get('Status')); print('ARN:', d.get('Arn',''))"

# ---------------------------------------------------------------------------
# Publish the latest version
# ---------------------------------------------------------------------------
echo "==> Publishing dashboard version"
VERSION=$(
  aws quicksight describe-dashboard \
    --aws-account-id "${ACCOUNT_ID}" \
    --dashboard-id   "${DASHBOARD_ID}" \
    --profile        "${PROFILE}" \
    --region         "${REGION}" \
    --query          'Dashboard.Version.VersionNumber' \
    --output         text
)

aws quicksight update-dashboard-published-version \
  --aws-account-id  "${ACCOUNT_ID}" \
  --dashboard-id    "${DASHBOARD_ID}" \
  --version-number  "${VERSION}" \
  --profile         "${PROFILE}" \
  --region          "${REGION}" \
  --output          json \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Published version:', d.get('DashboardId'), 'status', d.get('Status'))"

# ---------------------------------------------------------------------------
# Print the console URL
# ---------------------------------------------------------------------------
DASHBOARD_URL="https://${REGION}.quicksight.aws.amazon.com/sn/dashboards/${DASHBOARD_ID}"
echo ""
echo "======================================================================"
echo "  Dashboard deployed successfully!"
echo "  URL: ${DASHBOARD_URL}"
echo ""
echo "  Next steps:"
echo "  1. Open the URL above in your browser"
echo "  2. Take screenshots and save them to Lab5/docs/dashboard/"
echo "  3. Run: git add docs/dashboard/*.png && git commit -m 'lab5: dashboard screenshots'"
echo "======================================================================"
