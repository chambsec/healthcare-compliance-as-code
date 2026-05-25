package compliance.hipaa.lambda_vpc_test

import rego.v1
import data.compliance.hipaa.lambda_vpc

compliant := {"planned_values": {"root_module": {"resources": [{
  "address": "aws_lambda_function.intake",
  "type": "aws_lambda_function",
  "values": {
    "vpc_config": [{
      "subnet_ids": ["subnet-abc123", "subnet-def456"],
      "security_group_ids": ["sg-abc123"]
    }]
  }
}]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [{
  "address": "aws_lambda_function.intake",
  "type": "aws_lambda_function",
  "values": {
    "vpc_config": []
  }
}]}}}

test_compliant_passes if {
  count(lambda_vpc.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
  some msg in lambda_vpc.deny with input as noncompliant
  contains(msg, "GAP-05")
}