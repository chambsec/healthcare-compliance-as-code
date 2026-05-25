package compliance.hipaa.tls_enforce_test

import rego.v1
import data.compliance.hipaa.tls_enforce

compliant := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"bucket": "uploads"}
  },
  {
    "address": "aws_s3_bucket_policy.uploads_tls",
    "type": "aws_s3_bucket_policy",
    "values": {
      "bucket": "uploads",
      "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
    }
  }
]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"bucket": "uploads"}
  }
]}}}

test_compliant_passes if {
  count(tls_enforce.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
  some msg in tls_enforce.deny with input as noncompliant
  contains(msg, "GAP-03")
}