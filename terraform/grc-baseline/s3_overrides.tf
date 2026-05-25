# GAP-01: HIPAA 164.312(a)(2)(iv) - Replace SSE-S3 with CMK encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads_cmk" {
  bucket = var.starter_uploads_bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-03: HIPAA 164.312(e)(1) - Enforce TLS-only access to PHI bucket
resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = var.starter_uploads_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          var.starter_uploads_bucket_arn,
          "${var.starter_uploads_bucket_arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-04: HIPAA 164.308(a)(7) - Enable versioning for PHI recoverability
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = var.starter_uploads_bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}