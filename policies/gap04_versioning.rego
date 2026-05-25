# METADATA
# title: GAP-04 - S3 buckets storing PHI must have versioning enabled
# description: "PHI overwrites must be recoverable. S3 versioning must be enabled on all PHI buckets."
# custom:
#   control_id: HIPAA-164.308(a)(7)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-04
#   remediation: "Add aws_s3_bucket_versioning with status=Enabled referencing the PHI bucket."
package compliance.hipaa.versioning

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket"
	not has_versioning(r.address)
	msg := sprintf(
		"[HIPAA-164.308(a)(7)] [GAP-04] %s: S3 bucket storing PHI must have versioning enabled. PHI overwrites must be recoverable. Remediation: add aws_s3_bucket_versioning with status=Enabled.",
		[r.address],
	)
}

has_versioning(bucket_addr) if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	r.values.bucket == split(bucket_addr, ".")[1]
	r.values.versioning_configuration[0].status == "Enabled"
}