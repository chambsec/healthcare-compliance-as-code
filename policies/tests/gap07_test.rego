package compliance.hipaa.iam_least_privilege_test

import rego.v1
import data.compliance.hipaa.iam_least_privilege

compliant := {"planned_values": {"root_module": {"resources": [{
  "address": "aws_iam_role_policy.lambda_least_privilege",
  "type": "aws_iam_role_policy",
  "values": {
    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\",\"dynamodb:UpdateItem\",\"dynamodb:Query\"],\"Resource\":\"arn:aws:dynamodb:us-east-1:123:table/intake\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::uploads/*\"}]}"
  }
}]}}}

noncompliant := {"planned_values": {"root_module": {"resources": [{
  "address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy",
  "values": {
    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:us-east-1:123:table/intake\"},{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::uploads/*\"}]}"
  }
}]}}}

test_compliant_passes if {
  count(iam_least_privilege.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
  some msg in iam_least_privilege.deny with input as noncompliant
  contains(msg, "GAP-07")
}