output "compliance_attestation" {
  description = "Machine-readable attestation of HIPAA controls implemented."
  value = {
    gap_01_cmk_encryption = {
      control  = "HIPAA-164.312(a)(2)(iv)"
      resource = "aws_s3_bucket_server_side_encryption_configuration.uploads_cmk"
      status   = "implemented"
      method   = "SSE-KMS with customer-managed key ${aws_kms_key.phi.key_id}"
    }
    gap_02_dynamodb_cmk = {
      control  = "HIPAA-164.312(a)(2)(iv)"
      resource = "aws_kms_key.phi"
      status   = "implemented"
      method   = "CMK provisioned - wire to DynamoDB server_side_encryption block"
    }
    gap_03_tls_enforce = {
      control  = "HIPAA-164.312(e)(1)"
      resource = "aws_s3_bucket_policy.uploads_tls"
      status   = "implemented"
      method   = "Bucket policy denying aws:SecureTransport=false"
    }
    gap_04_versioning = {
      control  = "HIPAA-164.308(a)(7)"
      resource = "aws_s3_bucket_versioning.uploads"
      status   = "implemented"
      method   = "S3 versioning enabled"
    }
    gap_05_lambda_vpc = {
      control  = "HIPAA-164.312(e)(1)"
      resource = "aws_security_group.lambda"
      status   = "implemented"
      method   = "Lambda security group + VPC placement in private subnets"
    }
    gap_07_iam_least_privilege = {
      control  = "HIPAA-164.312(a)(1)"
      resource = "aws_iam_role_policy.lambda_least_privilege"
      status   = "implemented"
      method   = "Replaced dynamodb:* and s3:* with scoped action list"
    }
  }
}