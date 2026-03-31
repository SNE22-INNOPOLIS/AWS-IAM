resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.environment}-cloudtrail-logs-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_access" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_access.json
}

data "aws_iam_policy_document" "cloudtrail_access" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    principal { service = "cloudtrail.amazonaws.com" }
    action  = "s3:GetBucketAcl"
    resource = aws_s3_bucket.cloudtrail_logs.arn
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    principal { service = "cloudtrail.amazonaws.com" }
    action  = "s3:PutObject"
    resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}