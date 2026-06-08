-- ============================================================
-- Metric: SCP Violation Attempts
-- Table:  iam_health_db.scp_violations
-- Run in: Athena workgroup  iam-health-workgroup
--
-- Source: CloudTrail AccessDenied events where errorMessage
--   contains "Service Control Policy", "SCP", or references
--   an AWS Organizations policy.
-- The Lambda collects the previous 24 hours on each run,
-- so daily partitions give a point-in-time count.
-- ============================================================

-- ============================================================
-- Summary: today's SCP violation count + delta
-- ============================================================

WITH latest_partition AS (
    SELECT
        MAX(year)  AS max_year,
        MAX(month) AS max_month,
        MAX(day)   AS max_day
    FROM "iam_health_db"."scp_violations"
),

current_snapshot AS (
    SELECT v.*
    FROM "iam_health_db"."scp_violations" v
    JOIN latest_partition lp
      ON v.year  = lp.max_year
     AND v.month = lp.max_month
     AND v.day   = lp.max_day
),

previous_snapshot AS (
    SELECT v.*
    FROM "iam_health_db"."scp_violations" v
    WHERE CONCAT(v.year, '-', LPAD(v.month, 2, '0'), '-', LPAD(v.day, 2, '0'))
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
)

SELECT
    (SELECT COUNT(*) FROM current_snapshot)              AS violations_today,
    (SELECT COUNT(*) FROM previous_snapshot)             AS violations_yesterday,
    (SELECT COUNT(*) FROM current_snapshot)
    - (SELECT COUNT(*) FROM previous_snapshot)           AS change_day_over_day,
    (SELECT COUNT(DISTINCT username) FROM current_snapshot
     WHERE username IS NOT NULL)                         AS unique_principals_today,
    (SELECT COUNT(DISTINCT event_name) FROM current_snapshot) AS unique_api_calls_blocked;

-- ============================================================
-- Detail view: each SCP violation event (today)
-- ============================================================

SELECT
    event_id,
    event_name,
    CAST(event_time AS TIMESTAMP)                             AS event_time,
    username,
    error_code,
    SUBSTR(error_message, 1, 200)                             AS error_message_snippet,
    source_ip,
    aws_region,
    event_source,
    CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date
FROM "iam_health_db"."scp_violations"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          = (SELECT CAST(CONCAT(max_year, '-',
                                LPAD(CAST(max_month AS VARCHAR), 2, '0'), '-',
                                LPAD(CAST(max_day   AS VARCHAR), 2, '0'))
                         AS DATE)
             FROM (SELECT MAX(year) max_year, MAX(month) max_month, MAX(day) max_day
                   FROM "iam_health_db"."scp_violations"))
ORDER BY event_time DESC;

-- ============================================================
-- Trend view: daily SCP violation count over the last 30 days
-- This query powers the QuickSight line-chart visual.
-- ============================================================

SELECT
    CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
    COUNT(*)                                                                       AS violation_count,
    COUNT(DISTINCT username)                                                       AS unique_principals,
    COUNT(DISTINCT event_name)                                                     AS unique_api_calls,
    COUNT(DISTINCT aws_region)                                                     AS regions_affected
FROM "iam_health_db"."scp_violations"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY year, month, day
ORDER BY report_date;

-- ============================================================
-- Top offenders: principals triggering the most SCP denials
-- ============================================================

SELECT
    COALESCE(username, '(unknown)')                    AS principal,
    COUNT(*)                                           AS violation_count,
    COUNT(DISTINCT event_name)                         AS distinct_api_calls_blocked,
    MIN(CAST(event_time AS TIMESTAMP))                 AS first_seen,
    MAX(CAST(event_time AS TIMESTAMP))                 AS last_seen
FROM "iam_health_db"."scp_violations"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY username
ORDER BY violation_count DESC
LIMIT 20;
