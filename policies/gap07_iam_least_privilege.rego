# METADATA
# title: GAP-07 - Lambda IAM role must not use wildcard actions on PHI data stores
# description: "Lambda IAM policies must not use dynamodb:* or s3:* on PHI resources. Least privilege required."
# custom:
#   control_id: HIPAA-164.312(a)(1)
#   framework: hipaa-security-rule
#   severity: critical
#   gap: GAP-07
#   remediation: "Replace dynamodb:* and s3:* with scoped action lists: dynamodb:PutItem,GetItem,UpdateItem,Query and s3:PutObject,GetObject."
package compliance.hipaa.iam_least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "*"}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	stmt.Effect == "Allow"
	some action in to_array(stmt.Action)
	action in wildcard_actions
	msg := sprintf(
		"[HIPAA-164.312(a)(1)] [GAP-07] %s: IAM policy contains wildcard action '%s' on PHI data store. Remediation: replace with scoped action list (dynamodb:PutItem,GetItem,UpdateItem,Query or s3:PutObject,GetObject).",
		[r.address, action],
	)
}

to_array(x) := x if is_array(x)
to_array(x) := [x] if is_string(x)