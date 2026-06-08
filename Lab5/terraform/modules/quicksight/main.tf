# =============================================================================
# quicksight module
#
# Creates:
#   - IAM role allowing QuickSight to read from S3 and query Athena
#   - QuickSight data source (Athena)
#   - QuickSight datasets for each of the three dashboard metrics:
#       * unused_permissions_daily  → % roles with unused permissions
#       * stale_keys_daily          → count of access keys > 90 days
#       * scp_violations_daily      → daily SCP violation count (trend)
#
# The dashboard itself is deployed via scripts/quicksight/deploy_dashboard.sh
# because the QuickSight Terraform provider's dashboard definition API is
# extremely verbose; the shell script calls create-dashboard directly with
# the JSON from scripts/quicksight/dashboard_definition.json.
# =============================================================================

# ---------------------------------------------------------------------------
# IAM role for QuickSight to access Athena + S3
# ---------------------------------------------------------------------------

resource "aws_iam_role" "quicksight_athena" {
  name = "${var.project_name}-quicksight-athena"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "quicksight.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "quicksight_athena_permissions" {
  name = "${var.project_name}-quicksight-athena-permissions"
  role = aws_iam_role.quicksight_athena.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Athena — run queries
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:BatchGetQueryExecution",
          "athena:CancelQueryExecution",
          "athena:GetCatalogs",
          "athena:GetExecutionEngine",
          "athena:GetExecutionEngines",
          "athena:GetNamespace",
          "athena:GetNamespaces",
          "athena:GetQueryExecution",
          "athena:GetQueryExecutions",
          "athena:GetQueryResults",
          "athena:GetQueryResultsStream",
          "athena:GetTable",
          "athena:GetTables",
          "athena:ListQueryExecutions",
          "athena:RunQuery",
          "athena:StartQueryExecution",
          "athena:StopQueryExecution",
          "athena:ListWorkGroups",
          "athena:GetWorkGroup",
        ]
        Resource = "*"
      },
      # Glue — read catalog metadata
      {
        Sid    = "GlueCatalogRead"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:BatchGetPartition",
        ]
        Resource = "*"
      },
      # S3 — read findings data and write Athena results
      {
        Sid    = "S3FindingsAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:PutObject",
          "s3:ListBucketMultipartUploads",
          "s3:AbortMultipartUpload",
          "s3:CreateBucket",
        ]
        Resource = [
          "arn:aws:s3:::${var.findings_bucket_name}",
          "arn:aws:s3:::${var.findings_bucket_name}/*",
        ]
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# QuickSight data source — Athena
# ---------------------------------------------------------------------------

resource "aws_quicksight_data_source" "athena" {
  aws_account_id = var.account_id
  data_source_id = "${var.project_name}-athena"
  name           = "IAM Health — Athena"
  type           = "ATHENA"
  tags           = var.tags

  parameters {
    athena {
      work_group = var.athena_workgroup_name
    }
  }

  permission {
    actions   = [
      "quicksight:DescribeDataSource",
      "quicksight:DescribeDataSourcePermissions",
      "quicksight:PassDataSource",
      "quicksight:UpdateDataSource",
      "quicksight:DeleteDataSource",
      "quicksight:UpdateDataSourcePermissions",
    ]
    principal = var.quicksight_user_arn
  }

  ssl_properties {
    disable_ssl = false
  }
}

# ---------------------------------------------------------------------------
# Helper locals — SQL for each dataset
# Note: these reference the Glue tables by name. The Glue crawler creates
# table names derived from the S3 prefix structure:
#   findings/unused_role_permissions/ → table "unused_role_permissions"
#   findings/stale_access_keys/       → table "stale_access_keys"
#   findings/scp_violations/          → table "scp_violations"
# ---------------------------------------------------------------------------

locals {
  db = var.glue_database_name

  sql_unused_permissions = <<-SQL
    SELECT
      CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
      COUNT(*)                                                                       AS total_roles,
      SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)                   AS roles_with_unused_perms,
      ROUND(
          100.0 * SUM(CASE WHEN unused_services_count > 0 THEN 1 ELSE 0 END)
          / NULLIF(COUNT(*), 0), 1
      )                                                                              AS pct_roles_with_unused_permissions
    FROM "${local.db}"."unused_role_permissions"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -90, CURRENT_DATE)
    GROUP BY year, month, day
    ORDER BY report_date
  SQL

  sql_stale_keys = <<-SQL
    SELECT
      CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
      COUNT(*)                                                                       AS stale_key_count,
      MAX(CAST(age_days AS INTEGER))                                                 AS oldest_key_age_days
    FROM "${local.db}"."stale_access_keys"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -90, CURRENT_DATE)
    GROUP BY year, month, day
    ORDER BY report_date
  SQL

  sql_scp_violations = <<-SQL
    SELECT
      CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE) AS report_date,
      COUNT(*)                                                                       AS violation_count,
      COUNT(DISTINCT username)                                                       AS unique_principals,
      COUNT(DISTINCT event_name)                                                     AS unique_api_calls
    FROM "${local.db}"."scp_violations"
    WHERE CAST(CONCAT(year, '-', LPAD(month, 2, '0'), '-', LPAD(day, 2, '0')) AS DATE)
              >= DATE_ADD('day', -30, CURRENT_DATE)
    GROUP BY year, month, day
    ORDER BY report_date
  SQL
}

# ---------------------------------------------------------------------------
# QuickSight dataset — Unused Permissions (daily trend)
# ---------------------------------------------------------------------------

resource "aws_quicksight_data_set" "unused_permissions" {
  aws_account_id = var.account_id
  data_set_id    = "${var.project_name}-unused-permissions-daily"
  name           = "IAM — Unused Permissions Daily"
  import_mode    = "DIRECT_QUERY"
  tags           = var.tags

  physical_table_map {
    physical_table_map_id = "unused_permissions_query"
    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena.arn
      name            = "unused_permissions_daily"
      sql_query       = local.sql_unused_permissions

      columns {
        name = "report_date"
        type = "DATETIME"
      }
      columns {
        name = "total_roles"
        type = "INTEGER"
      }
      columns {
        name = "roles_with_unused_perms"
        type = "INTEGER"
      }
      columns {
        name = "pct_roles_with_unused_permissions"
        type = "DECIMAL"
      }
    }
  }

  permission {
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions",
      "quicksight:UpdateDataSet",
      "quicksight:DeleteDataSet",
      "quicksight:CreateIngestion",
      "quicksight:CancelIngestion",
      "quicksight:UpdateDataSetPermissions",
    ]
    principal = var.quicksight_user_arn
  }
}

# ---------------------------------------------------------------------------
# QuickSight dataset — Stale Access Keys (daily count)
# ---------------------------------------------------------------------------

resource "aws_quicksight_data_set" "stale_keys" {
  aws_account_id = var.account_id
  data_set_id    = "${var.project_name}-stale-keys-daily"
  name           = "IAM — Stale Access Keys Daily"
  import_mode    = "DIRECT_QUERY"
  tags           = var.tags

  physical_table_map {
    physical_table_map_id = "stale_keys_query"
    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena.arn
      name            = "stale_keys_daily"
      sql_query       = local.sql_stale_keys

      columns {
        name = "report_date"
        type = "DATETIME"
      }
      columns {
        name = "stale_key_count"
        type = "INTEGER"
      }
      columns {
        name = "oldest_key_age_days"
        type = "INTEGER"
      }
    }
  }

  permission {
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions",
      "quicksight:UpdateDataSet",
      "quicksight:DeleteDataSet",
      "quicksight:CreateIngestion",
      "quicksight:CancelIngestion",
      "quicksight:UpdateDataSetPermissions",
    ]
    principal = var.quicksight_user_arn
  }
}

# ---------------------------------------------------------------------------
# QuickSight dataset — SCP Violations (daily count, 30-day window)
# ---------------------------------------------------------------------------

resource "aws_quicksight_data_set" "scp_violations" {
  aws_account_id = var.account_id
  data_set_id    = "${var.project_name}-scp-violations-daily"
  name           = "IAM — SCP Violations Daily"
  import_mode    = "DIRECT_QUERY"
  tags           = var.tags

  physical_table_map {
    physical_table_map_id = "scp_violations_query"
    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena.arn
      name            = "scp_violations_daily"
      sql_query       = local.sql_scp_violations

      columns {
        name = "report_date"
        type = "DATETIME"
      }
      columns {
        name = "violation_count"
        type = "INTEGER"
      }
      columns {
        name = "unique_principals"
        type = "INTEGER"
      }
      columns {
        name = "unique_api_calls"
        type = "INTEGER"
      }
    }
  }

  permission {
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions",
      "quicksight:UpdateDataSet",
      "quicksight:DeleteDataSet",
      "quicksight:CreateIngestion",
      "quicksight:CancelIngestion",
      "quicksight:UpdateDataSetPermissions",
    ]
    principal = var.quicksight_user_arn
  }
}
