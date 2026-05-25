package compliance.hipaa.versioning_test

import rego.v1
import data.compliance.hipaa.versioning

compliant := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"bucket": "uploads"}
  },
  {
    "address": "aws_s3_bucket_versioning.uploads",
    "type": "aws_s3_bucket_versioning",
    "values": {
      "bucket": "uploads",
      "versioning_configuration": [{"status": "Enabled"}]
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
  count(versioning.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
  some msg in versioning.deny with input as noncompliant
  contains(msg, "GAP-04")
}