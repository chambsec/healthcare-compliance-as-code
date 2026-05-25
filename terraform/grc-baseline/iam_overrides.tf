# GAP-07: HIPAA 164.312(a)(1) - Replace wildcard IAM permissions with least privilege

resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-data-access-hipaa"
  role = var.starter_lambda_role_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBLeastPrivilege"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = var.starter_dynamodb_table_arn
      },
      {
        Sid    = "S3LeastPrivilege"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${var.starter_uploads_bucket_arn}/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# Allow Lambda to use VPC networking (needed for GAP-05)
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = var.starter_lambda_role_id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}