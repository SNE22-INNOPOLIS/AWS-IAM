-- ============================================================
-- Metric: % of IAM Roles with Unused Permissions
-- Table:  iam_health_db.unused_role_permissions
-- Run in: Athena workgroup  iam-health-workgroup
--
-- "Unused" = at least one IAM service the role has access to
--   was never authenticated against in the last 90 days
--   (as reported by IAM GenerateServiceLastAccessedDetails).
--
-- AWS service-linked roles and service roles are excluded;
-- the Lambda aggregator skips those paths automatically.
-- ============================================================

WITH latest_partition AS (
    -- Identify the most recent day of collected data
    SELECT
        MAX(year)  AS max_year,
        MAX(month) AS max_month,
        MAX(day)   AS max_day
    FROM "iam_health_db"."unused_role_permissions"
),

current_snapshot AS (
    SELECT r.*
    FROM "iam_health_db"."unused_role_permissions" r
    JOIN latest_partition lp
      ON r.year  = lp.max_year
     AND r.month = lp.max_month
     AND r.day   = lp.max_day
),

previous_snapshot AS (
    -- Yesterday's snapshot for trend comparison
    SELECT r.*
    FROM "iam_health_db"."unused_role_permissions" r
    WHERE CONCAT(r.year, '-', LPAD(r.month, 2, '0'), '-', LPAD(r.day, 2, '0'))
          = DATE_FORMAT(
                DATE_ADD('day', -1,
                    (SELECT CAST(CONCAT(max_year, '-',
                                        LPAD(CAST(max_month AS VARCHAR), 2, '0'), '-',
                                        LPAD(CAST(max_day   AS VARCHAR), 2, '0'))
                                 AS DATE)
                     FROM latest_partition)
                ),
                '%Y-%m-%d'
            )
),

today_metrics AS (
    SELECT
        COUNT(*)                                                                        AS total_roles,
        SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)                    AS roles_with_unused_permissions,
        ROUND(
            100.0 * SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
            1
        )                                                                               AS pct_roles_with_unused_permissions,
        ROUND(AVG(CAST(unused_services_percent AS DOUBLE)), 1)                         AS avg_unused_pct,
        MAX(CAST(unused_services_percent AS DOUBLE))                                   AS max_unused_pct_single_role
    FROM current_snapshot
),

yesterday_metrics AS (
    SELECT
        ROUND(
            100.0 * SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)
            / NULLIF(COUNT(*), 0),
            1
        ) AS pct_yesterday
    FROM previous_snapshot
)

SELECT
    t.total_roles,
    t.roles_with_unused_permissions,
    t.pct_roles_with_unused_permissions                                  AS pct_today,
    y.pct_yesterday,
    ROUND(t.pct_roles_with_unused_permissions - y.pct_yesterday, 1)      AS pct_change_day_over_day,
    t.avg_unused_pct,
    t.max_unused_pct_single_role
FROM today_metrics t
CROSS JOIN yesterday_metrics y;

-- ============================================================
-- Trend view: daily snapshots over the last 30 days
-- Use this query to drive the QuickSight line-chart dataset.
-- ============================================================

SELECT
    CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
    COUNT(*)                                                                       AS total_roles,
    SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)                   AS roles_with_unused_permissions,
    ROUND(
        100.0 * SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)
        / NULLIF(COUNT(*), 0),
        1
    )                                                                              AS pct_roles_with_unused_permissions,
    ROUND(AVG(CAST(unused_services_percent AS DOUBLE)), 1)                        AS avg_unused_pct
FROM "iam_health_db"."unused_role_permissions"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY year, month, day
ORDER BY report_date;
