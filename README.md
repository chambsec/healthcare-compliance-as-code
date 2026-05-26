# Acme Health Patient Intake API — CGE-P Capstone

**Candidate:** Chris Chambers
**Framework:** HIPAA Security Rule (Primary)
**Submission repo:** github.com/chambsec/healthcare-compliance-as-code

> Fork of GRCEngClub/cgep-app-starter — Patient Intake API wrapped with four CGE-P GRC layers.

## What was built

This repo wraps the deliberately non-compliant Acme Health Patient Intake API with:

- **Layer 1 — Terraform GRC baseline** (`terraform/grc-baseline/`) closing 6 of 8 HIPAA gaps
- **Layer 2 — Rego policy suite** (`policies/`) — 5 policies, 11 tests, all passing
- **Layer 3 — GitHub Actions pipeline** (`.github/workflows/`) — Plan → Conftest → Apply → Sign → Upload
- **Layer 4 — OSCAL component** (`oscal/`) — validated with trestle v4.0.3

## Gaps closed

| Gap | Issue | HIPAA Control | Status |
|-----|-------|--------------|--------|
| GAP-01 | S3 SSE-S3 → SSE-KMS CMK | 164.312(a)(2)(iv) | ✅ Terraform + Rego |
| GAP-02 | DynamoDB AWS-owned key → CMK | 164.312(a)(2)(iv) | ✅ Terraform + Rego |
| GAP-03 | No TLS enforce policy | 164.312(e)(1) | ✅ Terraform + Rego |
| GAP-04 | No S3 versioning | 164.308(a)(7) | ✅ Terraform + Rego |
| GAP-05 | Lambda not in VPC | 164.312(e)(1) | ✅ Terraform + Rego |
| GAP-06 | No DLQ/concurrency | SOC 2 CC7.2 | 📄 OSCAL documented |
| GAP-07 | IAM wildcard permissions | 164.312(a)(1) | ✅ Terraform + Rego |
| GAP-08 | No API Gateway logging/WAF | 164.312(b) | 📄 OSCAL documented |

## Verification

```bash
# Run policy tests
opa test ./policies

# Verify evidence chain of custody
bash scripts/verify-evidence.sh 26380796981 \
  --vault cgep-lab-grc-evidence-vault-95715f3d \
  --profile default

# Deploy the starter
make deploy AWS_PROFILE=default
make test AWS_PROFILE=default
```

## Design decisions and trade-offs

See `WRITEUP.md` for full explanation of framework choice, gap remediation strategy, and what would be done with another sprint.

