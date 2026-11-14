# Brief the CISO on the Identity Program

**TO:** Board Risk Committee | **DATE:** Nov 14, 2026 | **RE:** Post-Incident Identity Posture

## Status
**14 critical/high findings identified:** 5 Critical on-premises (service accounts + departed staff), 2 Critical AWS (public ePHI bucket + root account). **Attack path remains open:** service account credentials with Domain Admin access enable same lateral movement as Cobalt Strike incident.

**Incident Match:** Findings IAM-001, IAM-002, IAM-003 (three service accounts with standing Domain Admin), IAM-004/005/008 (departed staff with active accounts) directly recreate the attack path: workstation compromise → service account secret → admin privilege → breach.

**Current Risk:** 45% MFA coverage on privileged accounts; AWS root keys 4 years old, never rotated; ePHI backup bucket publicly readable.

## Completed
- Automated IAM audit script (`audit_iam.py`); quarterly scans identify drift
- Corrected cloud IAM policies (S3, KMS scoped to least-privilege; break-glass with MFA+IP gate)
- SAML SSO configuration reference; enables one-action off-boarding

## Next Actions (Immediate)
| Action | Owner | Target |
|---|---|---|
| Disable departed staff (3); remove DA from service accounts (3) | IT Security | Nov 21 |
| Block S3 public access; CloudTrail breach investigation | Cloud Security | Nov 15 |
| Enroll 6 users in MFA | IT Operations | Nov 21 |

## Authorization Requested
**18-Month Identity Program ($225K):** Vault+PAM ($150K), AWS Organizations+SCPs ($50K), hardware FIDO2 tokens ($25K), quarterly reviews (absorbed). Completes by Q3 2027. Without it: service account credentials remain unrotated; off-boarding continues to fail; MFA coverage stays at 45%.

## Board Resolution
**RESOLVED:** Authorize CISO to implement 18-month Identity Program with $225K budget, completion Q3 2027; immediate remediation of 14 critical/high findings by Nov 21, 2026.
