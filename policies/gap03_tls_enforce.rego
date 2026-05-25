# METADATA
# title: GAP-03 - S3 buckets must enforce TLS-only access
# description: "S3 buckets storing PHI must have a bucket policy denying requests where aws:SecureTransport is false."
# custom:
#   control_id: HIPAA-164.312(e)(1)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-03
#   remediation: "Add aws_s3_bucket_policy with a Deny statement on aws:SecureTransport=false."
package compliance.hipaa.tls_enforce

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	not has_tls_policy(r.address)
	msg := sprintf(
		"[HIPAA-164.312(e)(1)] [GAP-03] %s: S3 bucket must deny non-TLS requests. Remediation: add aws_s3_bucket_policy with Deny on aws:SecureTransport=false.",
		[r.address],
	)
}

has_tls_policy(bucket_addr) if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_policy"
	r.values.bucket == split(bucket_addr, ".")[1]
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	some condition_key in object.keys(stmt.Condition)
	lower(condition_key) == "bool"
	stmt.Condition[condition_key]["aws:SecureTransport"] == "false"
}