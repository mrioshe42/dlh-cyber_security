# 3. The Insider File

## Scenarios

1. **Shared PACS Login:** Radiology staff use a shared `raduser` account to prioritize workflow speed over accountability. This violates HIPAA audit trail requirements and prevents identification of unauthorized imaging access.
2. **Ghost Contractor Account:** A terminated contractor retained VPN access for 47 days due to a manual offboarding process. The account was used for off-hours reconnaissance, mirroring previous breach patterns.
3. **Personal NAS (Shadow IT):** A physician uses an unmanaged, unencrypted NAS for clinical data to bypass network latency. It serves as an unprotected repository for patient records, vulnerable to discovery or theft.
4. **Celebrity Patient Snooping:** A registration clerk accesses clinical records outside her job role out of curiosity. The EHR lacks RBAC and behavioral monitoring to flag this unauthorized "snooping."
5. **Plaintext Admin Credentials:** An overwhelmed sysadmin stores infrastructure passwords in plaintext files and shares them via email. This creates a single point of failure that could grant an attacker full administrative control.

## Insider Threat Classification

| Scenario | Classification | Primary Risk | Control Gap | Detection Method |
| --- | --- | --- | --- | --- |
| 1 | Negligent/Malicious | No accountability | No RBAC/Shared creds | Simultaneous IP logs |
| 2 | Malicious | Unauthorized access | No auto-offboarding | Off-hours access logs |
| 3 | Negligent | Data exposure | No endpoint mgmt/DLP | Network anomaly scan |
| 4 | Negligent | HIPAA breach | No RBAC/monitoring | Access outside job role |
| 5 | Negligent | Infra-takeover | No secret mgmt/MFA | File integrity/DLP |

## Pattern Assessment

MedDefense suffers from a systemic lack of **detective controls** and an over-reliance on **clinical workflow efficiency** at the expense of security. The organization lacks real-time audit logging, behavioral analytics to flag anomalous access (e.g., off-hours or outside job roles), and data loss prevention (DLP) tools. Access design is currently permissive, allowing shared credentials and shadow IT, because the primary goal is rapid clinical access. Consequently, insider threats remain invisible—functioning effectively as "legitimate" users—until an external complaint or accidental discovery reveals the breach.

## Key Controls

* **Technical:** Implementation of Role-Based Access Control (RBAC), Multi-Factor Authentication (MFA) for all administrative accounts, centralized secrets management (e.g., HashiCorp Vault), and deployment of behavioral monitoring/SIEM to detect anomalous access patterns.


* **Administrative:** Automated HR-linked account offboarding, robust Endpoint Management policies to block shadow IT, and formalizing credential handling procedures to prohibit plaintext storage.

## Impact Summary

Insider threats result in HIPAA violations (fines up to $100K per record), potential identity theft for patients, and infrastructure compromise. The lack of detective infrastructure leads to prolonged dwell times, where attackers or negligent insiders can manipulate or exfiltrate data undetected for weeks.
