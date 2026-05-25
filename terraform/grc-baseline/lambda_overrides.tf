# GAP-05: HIPAA 164.312(e)(1) - Deploy Lambda inside VPC for network isolation

resource "aws_security_group" "lambda" {
  name        = "acme-health-lambda-sg"
  description = "Security group for intake Lambda - no inbound, outbound to VPC only"
  vpc_id      = var.starter_vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.42.0.0/16"]
    description = "Allow outbound to VPC only"
  }

  tags = { Name = "acme-health-lambda-sg" }
}

resource "aws_lambda_function_event_invoke_config" "intake" {
  function_name = var.starter_lambda_function_name

  maximum_retry_attempts = 1
}

# VPC config override — moves Lambda into private subnets
# This closes GAP-05 by adding vpc_config to the existing function
resource "aws_lambda_function" "intake_vpc" {
  function_name = var.starter_lambda_function_name

  # These values must match the starter exactly
  handler  = "handler.handler"
  runtime  = "python3.12"
  role     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/acme-health-intake-lambda-${var.starter_lambda_function_name}"
  filename = "../lambda/handler.zip"
  timeout  = 10

  vpc_config {
    subnet_ids         = var.starter_private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      INTAKE_TABLE  = split("-submissions-", var.starter_lambda_function_name)[1]
      UPLOAD_BUCKET = var.starter_uploads_bucket_id
    }
  }

  lifecycle {
    ignore_changes = [
      filename,
      source_code_hash,
      last_modified
    ]
  }
}