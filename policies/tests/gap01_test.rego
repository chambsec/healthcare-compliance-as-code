package compliance.hipaa.cmk_encryption_test

import rego.v1
import data.compliance.hipaa.cmk_encryption

compliant_s3 := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"bucket": "uploads"}
  },
  {
    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads_cmk",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "values": {
      "bucket": "uploads",
      "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:us-east-1:123:key/abc"}]}]
    }
  },
  {
    "address": "aws_dynamodb_table.intake",
    "type": "aws_dynamodb_table",
    "values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}]}
  }
]}}}

noncompliant_s3 := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"bucket": "uploads"}
  },
  {
    "address": "aws_dynamodb_table.intake",
    "type": "aws_dynamodb_table",
    "values": {"server_side_encryption": []}
  }
]}}}

test_compliant_passes if {
  count(cmk_encryption.deny) == 0 with input as compliant_s3
}

test_noncompliant_s3_fails if {
  some msg in cmk_encryption.deny with input as noncompliant_s3
  contains(msg, "GAP-01")
}

test_noncompliant_dynamodb_fails if {
  some msg in cmk_encryption.deny with input as noncompliant_s3
  contains(msg, "GAP-02")
}