# HIPAA 164.312(a)(2)(iv): Encryption and decryption controls
# Customer-managed KMS key for PHI data stores (GAP-01, GAP-02)

resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI CMK - patient intake data"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 and DynamoDB to use the key"
        Effect = "Allow"
        Principal = {
          Service = ["s3.amazonaws.com", "dynamodb.amazonaws.com"]
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "acme-health-phi-cmk"
    Purpose = "phi-encryption"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}

output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "ARN of the PHI customer-managed KMS key."
}

output "phi_kms_key_id" {
  value       = aws_kms_key.phi.key_id
  description = "ID of the PHI customer-managed KMS key."
}