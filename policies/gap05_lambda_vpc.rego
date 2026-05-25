# METADATA
# title: GAP-05 - Lambda functions must run inside the VPC
# description: "Lambda functions processing PHI must be deployed inside a VPC with private subnets for network isolation."
# custom:
#   control_id: HIPAA-164.312(e)(1)
#   framework: hipaa-security-rule
#   severity: high
#   gap: GAP-05
#   remediation: "Add vpc_config block to aws_lambda_function referencing private subnet IDs and a security group."
package compliance.hipaa.lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_lambda_function"
	not has_vpc_config(r)
	msg := sprintf(
		"[HIPAA-164.312(e)(1)] [GAP-05] %s: Lambda function processing PHI must run inside a VPC. Remediation: add vpc_config with private subnet IDs and a security group.",
		[r.address],
	)
}

has_vpc_config(r) if {
	count(r.values.vpc_config) > 0
	count(r.values.vpc_config[0].subnet_ids) > 0
	count(r.values.vpc_config[0].security_group_ids) > 0
}