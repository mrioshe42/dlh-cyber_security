## Policy 1: MedDefenseSIEMLogReader Violations

**S3Access:** `s3:*` on `*`
- **Risk:** Delete any bucket, modify policies, access unrelated data; destroy evidence or exfiltrate data.
- **Fix:** `s3:GetObject, s3:ListBucket` → `meddefense-siemlog-prod` only

**CloudWatchAccess:** `logs:*, cloudwatch:*` on `*`
- **Risk:** Delete log groups, modify alarms, mask malicious activity, disable production alarms.
- **Fix:** `logs:CreateLogStream, logs:PutLogEvents` → `/aws/lambda/siem-log-reader` only

## Policy 2: MedDefenseEHRBackupRole Violations

**S3FullAccess:** `s3:*` on `*`
- **Risk:** Access any bucket (PHI, DICOM, configs), delete backups, expose data; ransomware deletion or HIPAA breach.
- **Fix:** `s3:PutObject, s3:GetObject, s3:ListBucket` → `meddefense-ehr-backup-prod` only

**KMSFullAccess:** `kms:*` on `*`
- **Risk:** Decrypt any key (prod, SSH, RDS), delete/modify keys; compromise encryption or disable it on live databases.
- **Fix:** `kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey` → `key/mrk-abc123def456` only

## Policy 3: MedDefenseBreakGlassAdmin Violations

**BreakGlassAdmin:** `*:*` with no conditions
- **Risk:** Unrestricted actions from anywhere, anytime; attacker can stage long undetected operations under emergency guise.
- **Fix:** Add explicit Deny (MFA absent or IP outside 198.51.100.0/24) + Allow with both conditions; gates access to emergency situations only.

## Least Privilege Summary

| Policy | Original | Corrected | Residual |
|---|---|---|---|
| SIEM Reader | `s3:*, logs:*, cloudwatch:*` on `*` | Single bucket + lambda logs | Log tampering in lambda namespace |
| EHR Backup | `s3:*, kms:*` on `*` | Backup bucket + one KMS key | Decrypt/generate on scoped key only |
| Break-Glass | `*:*` unrestricted | MFA + IP 198.51.100.0/24 gated | MFA/IP bypass if perimeter compromised |

## Residual Risk & Mitigations

**SIEM Reader:** Lambda log write allows tampering (mitigated: CloudTrail audit). Enable bucket versioning + MFA delete.

**EHR Backup:** KMS key can be used for decrypt/generate (mitigated: key policy denies DeleteKey/PutKeyPolicy; use key grants). Rotate credentials quarterly; CloudTrail all kms:Decrypt.

**Break-Glass:** MFA/IP bypassable if device or perimeter compromised. Use FIDO2 MFA; add out-of-band approval (Slack). Rotate annually; audit all uses within 24h.

**General:** Enable CloudTrail integrity; review quarterly; use Access Analyzer + IAM policy simulator.
