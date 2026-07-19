# 0. The Scan Report

## 1. Executive Summary

MedDefense is transitioning from reactive patching to a threat-informed strategy. With 31 vulnerabilities identified, we are prioritizing patient safety and data integrity within a $120,000 budget. This roadmap outlines the path from current "Level 1" maturity to a hardened, NIST-aligned posture.

## 2. Scan Metadata

* **Who/When:** Executed by SecurePoint Consulting, July 2026.
* **Policy:** Full internal `/16` "Deep" authenticated scan.
* **What was NOT scanned:** Cloud SaaS (O365), mobile fleet (iPads), and offline/air-gapped assets.
* **Constraints:** Non-intrusive checks only to preserve 24/7 clinical uptime.

## 3. Finding Distribution

* **Total:** 31 findings.
* **Breakdown:** 5 Critical, 7 High, 10 Medium, 5 Low, 4 Info.
* **Highest Severity:** **Medium (10 findings)**. This indicates widespread configuration decay and policy gaps rather than isolated software defects.

## 4. Asset Heat Map

Top 5 hosts by finding density (Cross-referenced with 1x00 Registry):

1. **billing-srv-01:** Financial/Payment backend (EOL OS).
2. **ehr-srv-01:** Core Clinical EHR (Ghostcat RCE).
3. **web-srv-01:** Patient Portal (DMZ-exposed).
4. **ad-dc-01:** Identity/Domain Controller (LDAP Relay).
5. **Alaris Pumps:** Clinical IoT (Dosage/Safety exposure).

## 5. First Observations

* **Patterns:** Critical findings are systemic, affecting core identity and clinical systems simultaneously.
* **Shadow IT:** Two undocumented devices (`10.10.2.99`, `10.10.10.200`) found running unauthorized development tools.
* **Surprise:** The prevalence of legacy EOL OS (Windows XP/Ubuntu 18.04) on critical medical hardware is higher than assumed in the initial 1x00 discovery.

## 6. Scan Limitations

* **Passive Nature:** The scan detects misconfigurations and known versions but does *not* confirm active exploitation or adversary intent.
* **Scope Gaps:** Does not assess SaaS identity providers or physical security controls, which are primary vectors for patient data exfiltration.

## 7. Critical Findings (Top 5)

| ID | Asset | Risk | Context |
| --- | --- | --- | --- |
| **031** | `ehr-srv-01` | RCE | Ghostcat; patient record exposure. |
| **003** | `billing-srv-01` | SQLi | Financial data extraction vector. |
| **007** | `ad-dc-01` | LDAP Relay | Domain admin takeover potential. |
| **010** | Alaris Pumps | DoS | Life-safety dosage control risk. |
| **004** | MRI Scanner | RCE (EOL) | Unpatchable XP; physical isolation req. |

## 8. Threat-Informed Remediation Roadmap ($120k Budget)

| Horizon | Focus | Cost |
| --- | --- | --- |
| **Immediate (48h)** | Patch RCEs, secure portals, EDR agent fix. | $15k |
| **Short-term (7d)** | Hardening (SMB/SNMP/GPOs). | $5k |
| **Medium-term (30d)** | App hardening, TLS/Cipher updates, ACLs. | $20k |
| **Long-term (90d)** | Micro-segmentation & EOL migration. | $80k |

## 9. Validation & Governance

* **Validation:** 72h post-patch re-scan and mandatory manual configuration audits.
* **Next Steps:** Transitioning to **1x03: Governance & Strategic Defense**. Activities include building a formal Risk Register, aligning with NIST CSF, and drafting a 6-month Board-funded security roadmap.
