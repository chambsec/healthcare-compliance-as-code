# METADATA
# title: GAP-01 / GAP-02 - PHI data stores must use customer-managed KMS keys
# description: "S3 buckets and DynamoDB tables storing PHI must use SSE-KMS with a CMK, not AWS-managed SSE-S3."
# custom:
#   control_id: HIPAA-164.312(a)(2)(iv)
#   framework: hipaa-security-rule
#   severity: critical
#   gap: GAP-01, GAP-02
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms and a customer kms_master_key_id. Add server_side_encryption block to aws_dynamodb_table with kms_key_arn."
package compliance.hipaa.cmk_encryption

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	not has_kms_encryption(r.address)
	msg := sprintf(
		"[HIPAA-164.312(a)(2)(iv)] [GAP-01] %s: S3 bucket storing PHI must use SSE-KMS with a customer-managed key, not SSE-S3. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms.",
		[r.address],
	)
}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_dynamodb_cmk(r)
	msg := sprintf(
		"[HIPAA-164.312(a)(2)(iv)] [GAP-02] %s: DynamoDB table storing PHI must use a customer-managed KMS key. Remediation: add server_side_encryption { enabled = true kms_key_arn = ... }.",
		[r.address],
	)
}

has_kms_encryption(bucket_addr) if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	r.values.bucket == split(bucket_addr, ".")[1]
	some rule in r.values.rule
	rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
	rule.apply_server_side_encryption_by_default[0].kms_master_key_id != null
	rule.apply_server_side_encryption_by_default[0].kms_master_key_id != ""
}

has_dynamodb_cmk(r) if {
	count(r.values.server_side_encryption) > 0
	r.values.server_side_encryption[0].enabled == true
	r.values.server_side_encryption[0].kms_key_arn != null
	r.values.server_side_encryption[0].kms_key_arn != ""
}