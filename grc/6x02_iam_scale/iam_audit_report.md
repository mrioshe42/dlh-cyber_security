# MedDefense IAM Audit Report

**Classification:** Confidential | **Date:** Nov 4, 2026 | **Prepared by:** Security Analyst | **Reviewed by:** James Chen

## Executive Summary

9 findings identified; 5 Critical. Service accounts with Domain Admin (svc_epic_int, svc_helpdesk, svc_backup) and departed contractors retaining DA (t.morrison, admin.legacy) directly mirror Cobalt Strike incident path: compromised endpoint → service account secret → DA compromise. Immediate action required (7 days) to remove standing DA credentials. MFA coverage: 45% of privileged accounts.

## Findings

| ID | Account (Row) | Severity | Issue | Risk | Remediation | Target |
|---|---|---|---|---|---|---|
| 001 | svc_epic_int (14) | Critical | DA, dormant 1156d, no function | Standing DA credential enables Cobalt Strike path | Disable or verify current function | 7d |
| 002 | svc_helpdesk (15) | Critical | DA, ticket automation | Over-privilege; vendor-granted | Remove from DA; add to Help Desk group | 7d |
| 003 | svc_backup (13) | Critical | DA, nightly backups | Over-privilege; backup compromise enables ransomware bypass | Remove from DA; add to Backup Operators | 7d |
| 004 | t.morrison (8) | Critical | DA + Server Admin, contract ended 9/2025 | Departed contractor retains admin access; dormant 248d | Disable account; remove groups | 24h |
| 005 | admin.legacy (7) | Critical | DA + no MFA, dormant 187d | Legacy account without MFA; migration complete 2021 | Disable account; remove DA | 24h |
| 006 | j.yamamoto (18) | High | DA + Server Admin, transferred IT→Finance 2/2024 | Privilege not removed after transfer; dormant 312d | Remove DA + Server Admin; verify Finance access | 7d |
| 007 | k.nguyen (10) | High | No MFA, 3 phishing failures, Epic+PACS access | High-risk clinical user without MFA | Enroll MFA; conduct phishing training | 7d |
| 008 | l.okafor (11) | High | Enabled, departed 11/28, Finance Users | Departed employee still enabled; last login 142d ago | Disable account; remove groups | 24h |
| 009 | b.carter (12) | Medium | Disabled but groups not removed (Server Admin, Helpdesk) | Re-enable risk if groups active | Remove groups from disabled account | 30d |


## MFA Coverage
- **Privileged (DA/SA):** 5/11 with MFA (45%) — HIPAA non-compliant
- **Clinical (Epic/PACS):** 2/4 with MFA (50%)
- **Service accounts:** N/A; need credential rotation policy

## Service Accounts
| Account | Groups | Function |
|---|---|---|
| svc_backup | DA | Backups (remove DA → Backup Ops) |
| svc_epic_int | DA | None identified; dormant 1156d (disable) |
| svc_helpdesk | DA | Ticket routing (remove DA → Help Desk) |
| svc_monitoring | Server Admin | Prometheus (acceptable) |
| svc_av_mgmt | Workstation Admin | EDR (acceptable) |

## Remediation (Prioritized)
| Priority | Action | Target |
|---|---|---|
| P0 | Disable admin.legacy, t.morrison, l.okafor | 24h |
| P0 | Remove DA from svc_epic_int, svc_helpdesk, svc_backup | 48h |
| P1 | Verify svc_epic_int function; remove j.yamamoto DA; enroll k.nguyen MFA | 7d |
| P2 | Clean b.carter groups; enforce MFA all privileged users | 30d |
| Ongoing | Quarterly access reviews; service account credential rotation | Monthly |
