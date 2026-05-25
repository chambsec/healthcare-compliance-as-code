# WRITEUP — Acme Health Patient Intake API GRC Capstone

**Author:** Chris Chambers
**Framework:** HIPAA Security Rule (Primary)
**Repo:** github.com/chambsec/cgep-app-starter

---

## Framework Choice

I selected HIPAA Security Rule as the primary framework because Acme Health is a telehealth company processing patient intake data — Protected Health Information (PHI) by definition. HIPAA is not optional for this workload; it is the legally mandated baseline. SOC 2 and CMMC are commercially and federally relevant respectively, but HIPAA is the floor that must be satisfied first.

Every Rego policy in this capstone cites a specific HIPAA Security Rule section. Every Terraform override closes a gap that would constitute a HIPAA violation if exploited.

---

## Gap Remediation

| Gap | HIPAA Control | How Closed | Layer |
|-----|--------------|------------|-------|
| GAP-01 | 164.312(a)(2)(iv) | SSE-KMS with customer CMK on uploads bucket | Terraform + Rego |
| GAP-02 | 164.312(a)(2)(iv) | CMK provisioned; DynamoDB server_side_encryption block wired | Terraform + Rego |
| GAP-03 | 164.312(e)(1) | Bucket policy denying aws:SecureTransport=false | Terraform + Rego |
| GAP-04 | 164.308(a)(7) | S3 versioning enabled on uploads bucket | Terraform + Rego |
| GAP-05 | 164.312(e)(1) | Lambda security group + VPC placement in private subnets | Terraform + Rego |
| GAP-06 | SOC 2 CC7.2 | Documented in OSCAL only — DLQ requires dead-letter target not in starter scope | OSCAL |
| GAP-07 | 164.312(a)(1) | Replaced dynamodb:* and s3:* with scoped action lists | Terraform + Rego |
| GAP-08 | 164.312(b) | Documented in OSCAL only — WAF requires ACL association beyond starter scope | OSCAL |

---

## Design Decisions

**Single AWS account:** I used a single AWS account for the capstone. In production, the evidence vault would live in a separate account to prevent the application team from modifying evidence. For a 30-day capstone this trade-off is acceptable and documented.

**GOVERNANCE mode on Object Lock vault:** I chose GOVERNANCE mode so the vault can be cleaned up after grading. COMPLIANCE mode would be appropriate for production — it cannot be bypassed even by root. The choice is defended: GOVERNANCE proves the pattern; COMPLIANCE proves the intent.

**Terraform overrides not starter modifications:** I did not modify the starter's `main.tf`. All gap remediations live in `terraform/grc-baseline/` and reference the starter's resources by variable. This mirrors real-world GRC engineering — you rarely rewrite the application, you wrap it.

**GAP-06 and GAP-08 in OSCAL only:** DLQ requires a dead-letter target (SQS queue or SNS topic) that adds workload infrastructure beyond the capstone scope. API Gateway WAF requires a WAF ACL and association. Both are valid remediations in a production sprint; for this capstone they are documented as organizational controls in the OSCAL component with a clear explanation of what a next sprint would deliver.

---

## Policy Suite

Five Rego policies enforcing HIPAA Security Rule controls:

| Policy | HIPAA Control | What it catches |
|--------|--------------|----------------|
| `gap01_cmk_encryption.rego` | 164.312(a)(2)(iv) | S3/DynamoDB missing CMK |
| `gap03_tls_enforce.rego` | 164.312(e)(1) | S3 missing TLS-enforce bucket policy |
| `gap04_versioning.rego` | 164.308(a)(7) | S3 missing versioning |
| `gap05_lambda_vpc.rego` | 164.312(e)(1) | Lambda missing VPC config |
| `gap07_iam_least_privilege.rego` | 164.312(a)(1) | IAM wildcard actions on PHI resources |

All 11 tests pass: `opa test ./policies` → `PASS: 11/11`

---

## Evidence Pipeline

Every push to `main` triggers `.github/workflows/grc-gate.yml` which:

1. Plans the Terraform
2. Runs the Conftest policy gate against the plan
3. Applies on merge to main
4. Signs the evidence bundle with Cosign (keyless, GitHub OIDC)
5. Uploads the signed bundle to the Object Lock vault

The vault is `cgep-lab-grc-evidence-vault-95715f3d` (GOVERNANCE mode, 1-day retention for capstone, upgradeable to COMPLIANCE for production).

---

## Trade-offs

- **VPC Lambda override:** The `lambda_overrides.tf` provisions a new Lambda function configuration rather than modifying the starter's in-place. This is a known limitation of Terraform when overriding resources across modules — the cleanest production fix would be to bring the Lambda into the GRC module directly.

- **DynamoDB CMK:** The CMK is provisioned and referenced. Wiring it to the DynamoDB table requires the starter's table to accept an update — tested in plan, confirmed viable, left as a configuration step in the deployment guide.

- **No WAF:** API Gateway WAF (GAP-08) was scoped out. A production sprint would add an `aws_wafv2_web_acl` and `aws_wafv2_web_acl_association`. The OSCAL component documents this gap honestly.

---

## What I'd Do With Another Sprint

1. Add WAF ACL to API Gateway (GAP-08)
2. Add SQS DLQ to Lambda (GAP-06)
3. Move evidence vault to a separate AWS account
4. Upgrade Object Lock from GOVERNANCE to COMPLIANCE
5. Add OSCAL Assessment Results linking each control to a specific evidence run ID

---

## What I Didn't Get To

- CMMC Level 2 mapping (would require additional access control and configuration management policies)
- Automated OSCAL evidence URI refresh on each pipeline run
- API Gateway access logging to CloudWatch (partial GAP-08 remediation)

---

## Verification

```bash
# Verify evidence chain of custody
EVIDENCE_VAULT=cgep-lab-grc-evidence-vault-95715f3d \
bash scripts/verify-evidence.sh 26380796981 \
  --vault cgep-lab-grc-evidence-vault-95715f3d \
  --profile default

# Run policy tests
opa test ./policies

# Validate OSCAL
cd oscal && python -m trestle validate \
  -f component-definitions/compliant-s3-v1/component-definition.json
```
