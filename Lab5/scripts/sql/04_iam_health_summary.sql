-- ============================================================
-- IAM Health Summary — Combined Scorecard
-- Tables:  iam_health_db.unused_role_permissions
--          iam_health_db.stale_access_keys
--          iam_health_db.scp_violations
--          iam_health_db.security_hub_findings
-- Run in: Athena workgroup  iam-health-workgroup
--
-- Returns one row per day covering all four metrics.
-- Use this as the base for a single QuickSight dataset that
-- drives a combined "health score" or executive summary table.
-- ============================================================

WITH date_spine AS (
    SELECT DISTINCT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date
    FROM "iam_health_db"."stale_access_keys"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)

    UNION

    SELECT DISTINCT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
    FROM "iam_health_db"."unused_role_permissions"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)

    UNION

    SELECT DISTINCT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
    FROM "iam_health_db"."scp_violations"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
),

unused_perms_daily AS (
    SELECT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
        COUNT(*)                                                                        AS total_roles,
        SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)                   AS roles_with_unused_perms,
        ROUND(
            100.0 * SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
            1
        )                                                                               AS pct_roles_with_unused_perms
    FROM "iam_health_db"."unused_role_permissions"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
    GROUP BY year, month, day
),

stale_keys_daily AS (
    SELECT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
        COUNT(*)                                                                        AS stale_key_count,
        MAX(CAST(age_days AS INTEGER))                                                  AS oldest_key_age_days
    FROM "iam_health_db"."stale_access_keys"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
    GROUP BY year, month, day
),

scp_violations_daily AS (
    SELECT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
        COUNT(*)                                                                        AS scp_violation_count,
        COUNT(DISTINCT username)                                                        AS unique_principals_blocked
    FROM "iam_health_db"."scp_violations"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
    GROUP BY year, month, day
),

securityhub_daily AS (
    SELECT
        CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
        COUNT(*)                                                                        AS total_iam_findings,
        SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END)             AS critical_high_findings
    FROM "iam_health_db"."security_hub_findings"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
    GROUP BY year, month, day
)

SELECT
    d.report_date,

    -- Unused permissions
    COALESCE(u.total_roles, 0)               AS total_roles_evaluated,
    COALESCE(u.roles_with_unused_perms, 0)   AS roles_with_unused_perms,
    COALESCE(u.pct_roles_with_unused_perms, 0) AS pct_roles_with_unused_perms,

    -- Stale keys
    COALESCE(k.stale_key_count, 0)           AS stale_key_count,
    COALESCE(k.oldest_key_age_days, 0)       AS oldest_key_age_days,

    -- SCP violations
    COALESCE(s.scp_violation_count, 0)       AS scp_violation_count,
    COALESCE(s.unique_principals_blocked, 0) AS unique_principals_blocked,

    -- Security Hub
    COALESCE(h.total_iam_findings, 0)        AS total_iam_findings,
    COALESCE(h.critical_high_findings, 0)    AS critical_high_findings,

    -- Composite health score (lower = worse):
    -- 100 - (unused_pct * 0.4) - (min(stale_keys * 5, 30)) - (min(scp_violations * 2, 20))
    -- Capped 0–100 for a quick executive RAG indicator.
    GREATEST(0, LEAST(100,
        ROUND(
            100.0
            - (COALESCE(u.pct_roles_with_unused_perms, 0) * 0.4)
            - (LEAST(COALESCE(k.stale_key_count, 0) * 5.0, 30.0))
            - (LEAST(COALESCE(s.scp_violation_count, 0) * 2.0, 20.0))
            - (LEAST(COALESCE(h.critical_high_findings, 0) * 2.0, 10.0)),
            0
        )
    ))                                       AS iam_health_score

FROM date_spine d
LEFT JOIN unused_perms_daily  u ON d.report_date = u.report_date
LEFT JOIN stale_keys_daily    k ON d.report_date = k.report_date
LEFT JOIN scp_violations_daily s ON d.report_date = s.report_date
LEFT JOIN securityhub_daily   h ON d.report_date = h.report_date
ORDER BY d.report_date;
