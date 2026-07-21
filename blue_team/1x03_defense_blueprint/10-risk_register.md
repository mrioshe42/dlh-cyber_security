# 10. The Risk Register

## Operational Risk Register

This Risk Register serves as the living governance instrument and single source of truth for MedDefense Health Systems' security program. It tracks the top 10 enterprise risks through their lifecycle, aligning quantitative financial metrics with operational treatments.

### Master Risk Register (Top 10 Risks)

| Field | RISK-001 | RISK-002 | RISK-003 | RISK-004 | RISK-005 |
| --- | --- | --- | --- | --- | --- |
| **Risk ID** | `RISK-001` | `RISK-002` | `RISK-003` | `RISK-004` | `RISK-005` |
| **Risk Description** | Ransomware encrypts EHR infrastructure, halting hospital-wide operations. | Attacker exfiltrates 50,000 patient health records from the EHR database. | Staff member inadvertently leaks sensitive PHI via USB or unencrypted channels. | Malware or attacker disrupts networked BD Alaris infusion pumps on the clinical floor. | Unsupported Windows XP MRI workstation serves as an internal lateral pivot point. |
| **Risk Category** | Operational | Compliance / Financial | Operational | Operational | Operational |
| **Threat Source** | Ransomware-as-a-Service (RaaS) Groups | Extortionists / Cybercriminals | Negligent Insiders / Staff | Opportunistic Attackers | Nation-State / Advanced PTTs |
| **Vulnerability** | `GAP-004` / `Finding-031` | `GAP-003` / `Finding-003` | `GAP-008` / `IAM-05` | `GAP-001` / `Finding-010` | `GAP-009` / `Sys-01` |
| **Affected Asset(s)** | `ehr-srv-01`, `ehr-db-01` | `ehr-db-01` (Patient Records) | 280 Clinical Workstations | BD Alaris Infusion Pumps | Siemens MAGNETOM MRI |
| **Likelihood (1-5)** | 4 (Likely) | 3 (Possible) | 4 (Likely) | 2 (Unlikely) | 3 (Possible) |
| **Impact (1-5)** | 5 (Catastrophic) | 4 (Major) | 3 (Moderate) | 4 (Major) | 3 (Moderate) |
| **Inherent Risk Score** | **20** | **12** | **12** | **8** | **9** |
| **ALE** | $1,567,500 | $701,250 | $300,000 | $92,750 | $71,200 |
| **Risk Owner** | Deputy CISO (James Chen) | IT Director (Sarah Park) | Privacy Officer / IT | Biomedical Engineering Lead | Infrastructure Lead |
| **Treatment Decision** | Mitigate | Mitigate | Mitigate | Mitigate | Mitigate |
| **Treatment Justification** | High ALE exposure requires urgent architectural hardening to prevent catastrophic downtime. | Encryption and log monitoring prevent extortion and regulatory penalties. | Endpoint controls and awareness reduce routine user-error leakage frequency. | General microsegmentation contains medical device exposure cost-effectively. | Inline hardware firewall insulates legacy OS without costly system replacement. |
| **Planned Control(s)** | MFA (Control 2) + VLAN Segmentation (Control 1) | Enterprise SIEM (Control 3) + DB Encryption | EDR Upgrade & USB Control (Control 5) | VLAN Microsegmentation (Control 1) | Inline Hardware Micro-Firewall (Control 6) |
| **Residual Risk** | Low (Score: 4) | Low (Score: 3) | Low (Score: 4) | Low (Score: 2) | Low (Score: 3) |
| **KRI** | Failed login spikes / VPN auth anomalies | Unauthorized DB query volume | Unencrypted USB insertion alerts | Unauthenticated IoT connection attempts | Legacy port scanning traffic spikes |
| **Review Date** | Monthly | Monthly | Monthly | Monthly | Monthly |

| Field | RISK-006 | RISK-007 | RISK-008 | RISK-009 | RISK-010 |
| --- | --- | --- | --- | --- | --- |
| **Risk ID** | `RISK-006` | `RISK-007` | `RISK-008` | `RISK-009` | `RISK-010` |
| **Risk Description** | Westside Clinic consumer router is compromised, providing a pivot into the core network. | Lack of centralized logging allows intruders to dwell undetected for months. | Ransomware destroys primary storage, and local backups lack offline immutability. | Shared administrative credentials (`raduser`) allow unmonitored lateral escalation. | Vacant CISO role leads to conflicting security priorities and governance paralysis. |
| **Risk Category** | Operational | Operational | Financial | Operational | Strategic |
| **Threat Source** | External Cybercriminals | Advanced Persistent Threats | RaaS Operators | Malicious/Compromised Insiders | Internal Management Friction |
| **Vulnerability** | `GAP-007` / `Net-03` | `GAP-002` / `Log-01` | `GAP-006` / `BC-01` | `GAP-005` / `IAM-02` | `GOV-01` / `Gov-Conflict` |
| **Affected Asset(s)** | Westside Clinic Router | All Enterprise Endpoints & Servers | Backup Appliance & NAS | Active Directory Domain Controllers | Executive Governance Structure |
| **Likelihood (1-5)** | 3 (Possible) | 4 (Likely) | 2 (Unlikely) | 3 (Possible) | 3 (Possible) |
| **Impact (1-5)** | 3 (Moderate) | 4 (Major) | 5 (Catastrophic) | 3 (Moderate) | 4 (Major) |
| **Inherent Risk Score** | **9** | **16** | **10** | **9** | **12** |
| **ALE** | $35,000 | $450,000 | $350,000 | $150,000 | N/A (Strategic) |
| **Risk Owner** | IT Director (Sarah Park) | Deputy CISO (James Chen) | Infrastructure Lead | IT Director (Sarah Park) | Executive Board / CFO |
| **Treatment Decision** | Mitigate | Mitigate | Mitigate | Mitigate | Mitigate |
| **Treatment Justification** | Replaces unmanaged hardware with enterprise firewall to secure remote traffic. | Centralized visibility is essential for catching threats before encryption occurs. | Immutable cloud storage guarantees ransomware recovery without ransom payments. | Enforces unique user attribution and eliminates shared account risks. | Establishing formal RACI resolves executive overlap between IT and Security. |
| **Planned Control(s)** | Westside Firewall (Control 6) | Enterprise SIEM (Control 3) | Offsite Backups (Control 4) | MFA Deployment (Control 2) | Governance RACI & CISO Charter |
| **Residual Risk** | Low (Score: 2) | Low (Score: 4) | Low (Score: 2) | Low (Score: 2) | Low (Score: 3) |
| **KRI** | Branch VPN tunnel drops / alert volume | SIEM agent offline status | Backup verification failure alerts | Shared account authentication frequency | Unresolved governance friction logs |
| **Review Date** | Monthly | Monthly | Monthly | Monthly | Monthly |


### Risk Register Governance Note

The Risk Register is maintained by Deputy CISO James Chen in coordination with IT Director Sarah Park, serving as MedDefense’s single source of truth for executive risk reporting. The register is formally reviewed on a monthly basis during security operations steering meetings and updated immediately when new threat intelligence or control deployments alter risk scores. An out-of-cycle review is automatically triggered by critical events such as zero-day vulnerabilities affecting medical infrastructure, major security incidents, or failed backup verifications. When a Key Risk Indicator (KRI) threshold is breached, the risk owner must submit an immediate mitigation escalation report to the CFO and executive leadership within 48 hours to determine if supplementary compensating controls or emergency contingency funds are required.
