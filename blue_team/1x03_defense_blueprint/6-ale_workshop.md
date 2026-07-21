# 6. The ALE Workshop

## The Quantitative ALE Workshop

To transform qualitative findings into financial justification for executive leadership, MedDefense’s top five operational risks are evaluated using quantitative Single Loss Expectancy ($SLE = AV \times EF$) and Annualized Loss Expectancy ($ALE = SLE \times ARO$) calculations.

### Risk 1: Ransomware Campaign Encrypts EHR & Core Infrastructure

* **Risk:** Ransomware deployment across Active Directory encrypts the EHR database and primary server infrastructure, halting clinical operations hospital-wide.
* **Source:** GAP-004 / Net-01 (Unpatched VPN/Perimeter), Finding 031 (Ghostcat RCE on `web-srv-01`) / Finding 007 (LDAP Relay), RaaS Groups (BlackReef / LockBit).
* **Asset:** EHR System (`ehr-srv-01` + `ehr-db-01`)
* **Asset Value (AV):** **$4,750,000**
* **Replacement/recovery cost:** $150,000 (Forensics, vendor incident response, and Active Directory forest rebuild)
* **Revenue loss during downtime:** $3,500,000 ($250,000/day hospital-wide revenue impact $\times$ 14 estimated downtime days)
* **Regulatory penalties:** $500,000 (HIPAA breach penalties for unencrypted patient data exposure)
* **Reputation/patient trust impact:** $600,000 (Estimated 5% patient diversion and attrition over 2 years)
* **Exposure Factor (EF):** **100%**
* **Reasoning:** A full ransomware encryption event renders the EHR completely offline, triggering total loss of operational capability until restored.
* **SLE:** $\$4,750,000 \times 1.00 = \mathbf{\$4,750,000}$
* **ARO:** **0.33** (Once every 3 years)
* **Reasoning:** Healthcare is the single most targeted sector for RaaS attacks. MedDefense’s unpatched edge devices, flat network, and lack of MFA make an attack highly probable within a 3-year window.
* **ALE:** $\$4,750,000 \times 0.33 = \mathbf{\$1,567,500 / \text{year}}$
* **Proposed Control:** MFA Deployment on VPN/Admin Accounts + 802.1Q Network Segmentation
* **Control Annual Cost:** $35,000 ($10,000 MFA setup + $25,000 Network Segmentation)
* **Estimated ALE After Control:** **$15,675** (MFA drops ARO to 0.033 by blocking credential entry; segmentation limits blast radius, dropping EF to 10%. $\$4,750,000 \times 0.10 \times 0.033 = \$15,675$)
* **Net Benefit:** $\$1,567,500 - \$15,675 - \$35,000 = \mathbf{\$1,516,825}$

### Risk 2: Patient Health Information (PHI) Exfiltration from Unencrypted EHR Database

* **Risk:** Attacker exfiltrates 50,000 patient records from `ehr-db-01` and demands an extortion payment to prevent public publication.
* **Source:** GAP-003 (No database encryption at rest) + Finding 003 (SQL Injection / Unrestricted DB access) + RaaS Groups / Extortionists (Kill Chain #1 & #3).
* **Asset:** `ehr-db-01` (50,000 Electronic Health Records)
* **Asset Value (AV):** **$2,125,000**
* **Replacement/recovery cost:** $50,000 (Database cleanup and digital forensics)
* **Revenue loss during downtime:** $0 (Data is exfiltrated covertly while system remains online)
* **Regulatory penalties:** $1,275,000 (HIPAA fines + mandatory breach notification infrastructure)
* **Reputation/patient trust impact:** $800,000 (Class-action litigation exposure and long-term brand damage)
* **Exposure Factor (EF):** **100%**
* **Reasoning:** A successful SQL injection or database dump exfiltrates the entire unencrypted patient population table.
* **SLE:** $\$2,125,000 \times 1.00 = \mathbf{\$2,125,000}$
* **ARO:** **0.33** (Once every 3 years)
* **Reasoning:** Automated web application scanners continuously target healthcare portals, and `billing-srv-01` has already suffered undetected compromise.
* **ALE:** $\$2,125,000 \times 0.33 = \mathbf{\$701,250 / \text{year}}$
* **Proposed Control:** Enterprise SIEM Deployment (Wazuh) + Database-at-Rest Encryption (AES-256)
* **Control Annual Cost:** $36,000
* **Estimated ALE After Control:** **$70,125** (SIEM detection alerts on mass queries and encryption renders exfiltrated data unreadable, reducing EF to 10%. $\$212,500 \times 0.33 = \$70,125$)
* **Net Benefit:** $\$701,250 - \$70,125 - \$36,000 = \mathbf{\$595,125}$

### Risk 3: Negligent Insider Data Leakage & Credential Misuse

* **Risk:** Healthcare worker exposes patient records via unencrypted USB drives, shadow IT applications, or credential misuse.
* **Source:** GAP-008 / IAM-05 (Lack of privileged account monitoring, shared `raduser` credentials, no USB/DLP controls) + Negligent Insiders.
* **Asset:** 280 Clinical Workstations & Active Directory Credentials
* **Asset Value (AV):** **$120,000** (Per Incident)
* **Replacement/recovery cost:** $30,000 (Internal forensic investigation and workstation re-imaging)
* **Revenue loss during downtime:** $0
* **Regulatory penalties:** $25,000 (HIPAA self-reporting costs)
* **Reputation/patient trust impact:** $65,000 (Targeted patient notification and credit monitoring services)
* **Exposure Factor (EF):** **100%**
* **Reasoning:** Each individual insider leakage event incurs the full procedural and regulatory cost required to contain and report the breach.
* **SLE:** $\$120,000 \times 1.00 = \mathbf{\$120,000}$
* **ARO:** **2.50** (2.5 incidents per year)
* **Reasoning:** MedDefense employs ~2,000 staff members with zero security awareness training, unrestricted USB ports, shared accounts, and no DLP controls.
* **ALE:** $\$120,000 \times 2.50 = \mathbf{\$300,000 / \text{year}}$
* **Proposed Control:** EDR Upgrade (Sophos Intercept X) with USB Control + Unique Attributable Credentials
* **Control Annual Cost:** $30,000
* **Estimated ALE After Control:** **$60,000** (Policy enforcement and EDR peripheral blocking drop the incident frequency ARO from 2.5 to 0.5 per year. $\$120,000 \times 0.5 = \$60,000$)
* **Net Benefit:** $\$300,000 - \$60,000 - \$30,000 = \mathbf{\$210,000}$

### Risk 4: Clinical Disruption via Medical Device Compromise

* **Risk:** Malware or an opportunistic attacker manipulates or disables networked BD Alaris infusion pumps across the clinical floor.
* **Source:** GAP-001 / Net-04 (No medical IoT segmentation) + Finding 010 (Alaris Pump default credentials) / Finding 016 (Philips Monitor), Opportunistic Attackers.
* **Asset:** BD Alaris Infusion Pumps (~120 units) & Medical IoT Subnet
* **Asset Value (AV):** **$1,855,000**
* **Replacement/recovery cost:** $105,000 (Vendor re-imaging and firmware validation)
* **Revenue loss during downtime:** $100,000 ($20,000/day $\times$ 5 days operating on manual dosing protocols)
* **Regulatory penalties:** $150,000 (FDA Sentinel Event investigation)
* **Reputation/patient trust impact:** $1,500,000 (Malpractice liability exposure resulting from potential dosing errors)
* **Exposure Factor (EF):** **50%**
* **Reasoning:** An attack impacts a portion of the pump fleet or causes partial operational disruption before pumps are isolated.
* **SLE:** $\$1,855,000 \times 0.50 = \mathbf{\$927,500}$
* **ARO:** **0.10** (Once every 10 years)
* **Reasoning:** While targeted medical device attacks are rare, unauthenticated access and default passwords on a flat network make opportunistic disruption plausible.
* **ALE:** $\$927,500 \times 0.10 = \mathbf{\$92,750 / \text{year}}$
* **Proposed Control:** 802.1Q Microsegmentation (Dedicated Medical IoT VLAN) & Password Hardening
* **Control Annual Cost:** $10,000 (Allocated portion of overall network segmentation budget)
* **Estimated ALE After Control:** **$9,275** (VLAN isolation prevents general network access, reducing ARO to 0.01. $\$927,500 \times 0.01 = \$9,275$)
* **Net Benefit:** $\$92,750 - \$9,275 - \$10,000 = \mathbf{\$73,475}$


### Risk 5: Persistent Foothold via Legacy Windows XP Embedded MRI System

* **Risk:** An attacker exploits legacy vulnerabilities on the Windows XP MRI scanner to establish a persistent foothold within the network.
* **Source:** GAP-009 / Sys-01 (Windows XP Embedded on MRI) + Legacy OS Vulnerabilities (EternalBlue / Conficker), Nation-State / Sophisticated Attackers.
* **Asset:** Siemens MAGNETOM MRI Scanner
* **Asset Value (AV):** **$445,000**
* **Replacement/recovery cost:** $40,000 (Specialized vendor system restore and MRI re-calibration)
* **Revenue loss during downtime:** $105,000 ($15,000/day diagnostic imaging loss $\times$ 7 days offline)
* **Regulatory penalties:** $100,000 (The Joint Commission sentinel audit and regulatory reporting)
* **Reputation/patient trust impact:** $200,000 (Patient care delays and diverted outpatient procedures)
* **Exposure Factor (EF):** **80%**
* **Reasoning:** Exploitation renders the diagnostic workstation unusable, forcing an operational shutdown of the MRI unit.
* **SLE:** $\$445,000 \times 0.80 = \mathbf{\$356,000}$
* **ARO:** **0.20** (Once every 5 years)
* **Reasoning:** Windows XP has been unsupported since 2014; exposure on a flat network guarantees eventual exploitation by automated network worms or pivoting attackers.
* **ALE:** $\$356,000 \times 0.20 = \mathbf{\$71,200 / \text{year}}$
* **Proposed Control:** Inline Hardware Micro-Firewall (Hardware Bridge restricting MRI traffic strictly to PACS)
* **Control Annual Cost:** $4,000
* **Estimated ALE After Control:** **$7,120** (Hardware bridge insulates legacy OS from general network traffic, dropping ARO to 0.02. $\$356,000 \times 0.02 = \$7,120$)
* **Net Benefit:** $\$71,200 - \$7,120 - \$4,000 = \mathbf{\$60,080}$


### Risk Prioritization by ALE

The top 5 risks are ranked below by total financial exposure ($\text{ALE}_{\text{Before}}$):

| Rank | Risk Description | Primary Asset | Baseline SLE | Baseline ARO | Baseline ALE | Proposed Control | Post-Control ALE | Net Benefit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **1** | **Ransomware EHR Encryption** | EHR System (`ehr-srv-01`) | $4,750,000 | 0.33 | **$1,567,500** | MFA + Network Segmentation | $15,675 | **$1,516,825** |
| **2** | **PHI Data Exfiltration** | EHR Database (`ehr-db-01`) | $2,125,000 | 0.33 | **$701,250** | Enterprise SIEM + DB Encryption | $70,125 | **$595,125** |
| **3** | **Negligent Insider Data Leakage** | Workstations & AD Credentials | $120,000 | 2.50 | **$300,000** | Sophos EDR Upgrade + IAM Controls | $60,000 | **$210,000** |
| **4** | **Medical Device Disruption** | BD Alaris Infusion Pumps | $927,500 | 0.10 | **$92,750** | Medical IoT VLAN Microsegmentation | $9,275 | **$73,475** |
| **5** | **Legacy MRI System Exploitation** | Siemens MAGNETOM MRI | $356,000 | 0.20 | **$71,200** | Inline Hardware Micro-Firewall | $7,120 | **$60,080** |
