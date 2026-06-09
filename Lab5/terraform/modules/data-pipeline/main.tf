terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# =============================================================================
# data-pipeline module
#
# Creates:
#   - S3 bucket for NDJSON findings (versioned, encrypted, lifecycle)
#   - Athena workgroup with S3 results location
#   - Glue catalog database
#   - Glue crawler IAM role + policy
#   - Glue crawler (daily schedule)
# =============================================================================

# ---------------------------------------------------------------------------
# S3 — findings storage
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "findings" {
  bucket = "${var.project_name}-findings-${var.account_id}"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    id     = "expire-old-findings"
    status = "Enabled"
    filter {}

    expiration {
      days = var.findings_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Deny any request that does not use TLS
resource "aws_s3_bucket_policy" "findings_enforce_tls" {
  bucket = aws_s3_bucket.findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.findings.arn,
          "${aws_s3_bucket.findings.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Athena workgroup
# ---------------------------------------------------------------------------

resource "aws_athena_workgroup" "iam_health" {
  name          = "${var.project_name}-workgroup"
  force_destroy = true
  tags          = var.tags

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.findings.bucket}/athena-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }

    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.athena_bytes_scanned_cutoff
  }
}

# ---------------------------------------------------------------------------
# Glue catalog database
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_database" "iam_health" {
  name = replace("${var.project_name}_db", "-", "_")
}

# ---------------------------------------------------------------------------
# Glue crawler — IAM role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "glue_crawler" {
  name = "${var.project_name}-glue-crawler"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3_read" {
  name = "${var.project_name}-glue-s3-read"
  role = aws_iam_role.glue_crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadFindings"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation",
      ]
      Resource = [
        aws_s3_bucket.findings.arn,
        "${aws_s3_bucket.findings.arn}/*",
      ]
    }]
  })
}

# ---------------------------------------------------------------------------
# Glue crawler
# ---------------------------------------------------------------------------

resource "aws_glue_crawler" "iam_findings" {
  name          = "${var.project_name}-crawler"
  database_name = aws_glue_catalog_database.iam_health.name
  role          = aws_iam_role.glue_crawler.arn
  schedule      = var.glue_crawler_schedule
  tags          = var.tags

  s3_target {
    path = "s3://${aws_s3_bucket.findings.bucket}/findings/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  recrawl_policy {
    recrawl_behavior = "CRAWL_NEW_FOLDERS_ONLY"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = { AddOrUpdateBehavior = "InheritFromTable" }
      Tables     = { AddOrUpdateBehavior = "MergeNewColumns" }
    }
    Grouping = {
      TableGroupingPolicy     = "CombineCompatibleSchemas"
      TableLevelConfiguration = 3
    }
  })
}
