-- ============================================================
-- Metric: Count of Active IAM Access Keys > 90 Days Old
-- Table:  iam_health_db.stale_access_keys
-- Run in: Athena workgroup  iam-health-workgroup
--
-- The Lambda only writes keys that meet BOTH conditions:
--   1. Status = 'Active'
--   2. Age > KEY_AGE_THRESHOLD_DAYS (default 90)
-- So a COUNT(*) of the latest partition = the raw number.
-- ============================================================

WITH latest_partition AS (
    SELECT
        MAX(year)  AS max_year,
        MAX(month) AS max_month,
        MAX(day)   AS max_day
    FROM "iam_health_db"."stale_access_keys"
),

current_snapshot AS (
    SELECT k.*
    FROM "iam_health_db"."stale_access_keys" k
    JOIN latest_partition lp
      ON k.year  = lp.max_year
     AND k.month = lp.max_month
     AND k.day   = lp.max_day
),

previous_snapshot AS (
    SELECT k.*
    FROM "iam_health_db"."stale_access_keys" k
    WHERE CONCAT(k.year, '-', LPAD(k.month, 2, '0'), '-', LPAD(k.day, 2, '0'))
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
    (SELECT COUNT(*) FROM current_snapshot)  AS stale_key_count_today,
    (SELECT COUNT(*) FROM previous_snapshot) AS stale_key_count_yesterday,
    (SELECT COUNT(*) FROM current_snapshot)
    - (SELECT COUNT(*) FROM previous_snapshot)    AS change_day_over_day,
    (SELECT MAX(CAST(age_days AS INTEGER)) FROM current_snapshot) AS oldest_key_age_days,
    (SELECT AVG(CAST(age_days AS DOUBLE)) FROM current_snapshot)  AS avg_key_age_days;

-- ============================================================
-- Detail view: every stale key with owner and last-used info
-- Useful for a QuickSight table visual or exported CSV.
-- ============================================================

SELECT
    username,
    access_key_id,
    CAST(age_days AS INTEGER)                      AS age_days,
    create_date,
    last_used_date,
    last_used_service,
    last_used_region,
    CASE
        WHEN last_used_date IS NULL THEN 'Never used'
        WHEN CAST(age_days AS INTEGER) > 180       THEN 'Critical (>180d)'
        WHEN CAST(age_days AS INTEGER) > 90        THEN 'Warning (>90d)'
        ELSE 'OK'
    END                                            AS risk_level,
    CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date
FROM "iam_health_db"."stale_access_keys"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          = (SELECT CAST(CONCAT(max_year, '-',
                                LPAD(CAST(max_month AS VARCHAR), 2, '0'), '-',
                                LPAD(CAST(max_day   AS VARCHAR), 2, '0'))
                         AS DATE)
             FROM (SELECT MAX(year) max_year, MAX(month) max_month, MAX(day) max_day
                   FROM "iam_health_db"."stale_access_keys"))
ORDER BY CAST(age_days AS INTEGER) DESC;

-- ============================================================
-- Trend view: daily stale-key count over the last 30 days
-- ============================================================

SELECT
    CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
    COUNT(*)                                                                       AS stale_key_count,
    MAX(CAST(age_days AS INTEGER))                                                 AS oldest_key_age_days,
    AVG(CAST(age_days AS DOUBLE))                                                  AS avg_key_age_days
FROM "iam_health_db"."stale_access_keys"
WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
          >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY year, month, day
ORDER BY report_date;
