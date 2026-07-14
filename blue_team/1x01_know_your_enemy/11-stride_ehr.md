# 11. STRIDE on the EHR

This inventory applies the STRIDE model to the EHR architecture (`ehr-srv-01`, `ehr-db-01`, and associated clinical workstations) to systematically identify critical threats.

| Category | Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| **Spoofing** | EHR-S1 | Attacker spoofs a clinician workstation to send fraudulent drug orders. | Default/Shared Credentials | Patient harm/medication error | IAM-02 (MFA) | IAM-04 |
|  | EHR-S2 | Attacker spoofs the EHR database server to provide fake clinical data to workstations. | Vulnerable Software | Misdiagnosis/delayed care | None | Net-04 |
| **Tampering** | EHR-T1 | Attacker modifies patient allergy data in the PostgreSQL database. | Insider (Malicious) | Life-threatening medical errors | None | SEC-02 |
|  | EHR-T2 | Attacker alters EHR log files on `ehr-srv-01` to hide unauthorized access. | Privilege Abuse | Undetected data breach | None | SEC-01 |
| **Repudiation** | EHR-R1 | Clinician denies performing a specific data export of PHI for sale. | Insider (Malicious) | Inability to attribute theft | None | SEC-02 |
|  | EHR-R2 | Unauthorized user performs bulk download but denies the action due to log gaps. | Privilege Abuse | Regulatory non-compliance | None | SEC-01 |
| **Info Disclosure** | EHR-I1 | Attacker queries PostgreSQL (5432) directly to exfiltrate 50,000 records. | Open Service Ports | Massive HIPAA breach | Net-04 (VLAN) | Net-02 |
|  | EHR-I2 | Attacker intercepts unencrypted traffic between workstation and EHR server. | Unsecure Networks | Exposure of patient PHI | Net-06 | Net-04 |
| **DoS** | EHR-D1 | Ransomware encrypts the `ehr-db-01` PostgreSQL data files. | Ransomware | Complete clinical shutdown | BKP-02 | BKP-02 |
|  | EHR-D2 | Malicious script floods `ehr-srv-01` with requests, crashing the app. | Open Service Ports | Inability to access records | None | Net-02 |
| **Elevation** | EHR-E1 | User uses exploit on Windows Server 2012 R2 to become Domain Admin. | Unsupported Systems | Total environment compromise | None | Sys-01 |
|  | EHR-E2 | Attacker leverages excessive service account permissions on the EHR app. | Privilege Abuse | Unauthorized EHR control | None | IAM-05 |

## STRIDE Summary for EHR

The **Information Disclosure** category represents the greatest risk for MedDefense's EHR system. While Denial of Service (Ransomware) causes the most immediate operational disruption, the illicit exfiltration of sensitive patient records is uniquely dangerous in a healthcare context because it results in permanent, irreversible loss of patient confidentiality and massive regulatory liabilities under HIPAA. Because the EHR database currently resides within a flat network with open ports accessible to any compromised workstation, the cost to an attacker for exfiltrating 50,000 records is exceptionally low, whereas the long-term cost to MedDefense—including litigation, loss of patient trust, and irreparable reputation damage—is catastrophic.
