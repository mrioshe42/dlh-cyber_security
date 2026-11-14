# Assess the Cloud Security Posture

**Date:** Nov 14, 2026 | **Benchmark:** CIS AWS Foundations v3.0 | **Account:** 123456789012

**Scope:** IAM (root, users, MFA, keys, policy), logging (CloudTrail, VPC Flow Logs), data (S3, encryption), governance (Organizations, SCPs)

## Findings Table

| ID | Observation | CIS Control | Severity | Status | Compliance |
|---|---|---|---|---|---|
| 1 | Root account no MFA; root keys exist (2022-03-15) | 1.1, 1.2, 1.4 | Critical | Non-Compliant | FAILED |
| 2 | 3/7 IAM console users no MFA | 1.12 | High | Non-Compliant | FAILED |
| 3 | 2 long-lived access keys (22+ mo, no rotation) | 1.17 | Medium | Non-Compliant | FAILED |
| 4 | Weak password policy (8 char, no complexity, no expiry) | 1.6-1.8 | Medium | Non-Compliant | FAILED |
| 5 | CloudTrail disabled in us-east-2 (DR region) | 3.1 | High | Non-Compliant | FAILED |
| 6 | S3 ePHI bucket public (Principal:*, s3:GetObject) | 3.17, 3.20 | Critical | Non-Compliant | FAILED |
| 7 | Three roles with AdministratorAccess policy | 1.16 | High | Non-Compliant | FAILED |
| 8 | VPC Flow Logs disabled on all VPCs | 3.8 | Medium | Non-Compliant | FAILED |
| 9 | EHR backup role: s3:* on Resource:* (Task 2 pre-correction) | 1.16 | High | **REMEDIATED** | COMPLIANT |
| 10 | AWS Organizations/SCPs not configured | 4.1 | Medium | Non-Compliant | FAILED |

## Critical Findings

**Finding 1: Root MFA + Keys**
- **Issue:** No MFA; root keys 4 years old, never deleted
- **Risk:** Full account takeover; undetectable persistence
- **HIPAA:** 164.312(d) requires accountability; root violates unique ID
- **Fix:** (1) Enable MFA (AWS Console → Account → Root account security → MFA) (2) Delete root keys (Security Credentials → Access keys → Delete)
- **Target:** 24h | **Owner:** Cloud Ops

**Finding 6: Public ePHI S3 Bucket**
- **Issue:** `meddefense-clinical-backup-2022` has Block Public Access **disabled**; bucket policy `Principal: "*"` allows `s3:GetObject`
- **Risk:** Any user can access ePHI backups (patient names, MRNs, diagnoses, medications)
- **HIPAA 164.402 Breach:** Unauthorized access to PHI → breach event if discovered; 164.404 requires notification within 60 days
- **Fix:** (1) S3 Console → Block Public Access → Enable all 4 settings (1h) (2) Update bucket policy: `Principal: {"AWS": "arn:aws:iam::123456789012:role/MedDefenseEHRBackupRole"}` (3) CloudTrail: query s3:GetObject calls from unauthenticated principal past 90d; if found → breach protocol
- **Target:** 1h | **Owner:** Cloud Security

## Remediation Roadmap

| Priority | Finding | Action | Target | Owner |
|---|---|---|---|---|
| **P0** | #6 Public S3 | Block public access; fix policy to role ARN only | 1h | Cloud Security |
| **P0** | #1 Root | Enable MFA; delete root keys | 24h | Cloud Ops |
| **P1** | #5 CloudTrail | Enable all regions (us-east-2) | 7d | Cloud Ops |
| **P1** | #2 IAM MFA | Enforce for 3 users: `aws iam put-user-policy --user-name <USER> --policy-name RequireMFA --policy-document '{"Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}'` | 7d | Cloud Ops |
| **P1** | #7 Admin roles | Remove AdministratorAccess from MedDefenseDevRole, MedDefenseLegacyRole, MedDefenseVendorAccess; apply least-privilege | 7d | Cloud Security |
| **P1** | #9 Backup role | Apply corrected policy: `aws iam put-role-policy --role-name MedDefenseEHRBackupRole --policy-name EHRBackupPolicy --policy-document file://iam_policies/ehr_backup_policy.json` | 7d | Cloud Ops |
| **P2** | #3 Keys | Rotate keys >90d old: `aws iam create-access-key --user-name <USER>` + test + `aws iam update-access-key --user-name <USER> --access-key-id <OLD> --status Inactive` | 30d | Cloud Ops |
| **P2** | #4 Password policy | `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --expire-passwords --max-password-age 90 --password-reuse-prevention 24` | 30d | Cloud Ops |
| **P2** | #8 VPC Flow Logs | Enable on all VPCs; send to CloudWatch Logs | 30d | Cloud Ops |
| **P2** | #10 Organizations | Enable; create baseline SCPs | 30d | Cloud Ops |

## Effort: ~12 hours over 7-30 days (P0 immediately + P1 within 7 days + P2 within 30 days)
