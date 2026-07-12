## 5: The Missing Pieces

### Control Gaps Analysis

| Gap ID | Gap Description | Category × Function Missing | Affected Asset(s) or Zone | Risk if Unaddressed |
|--------|-----------------|----------------------------|--------------------------|-------------------|
| **G-001** | No Detective controls for network traffic | Technical Detective | Core network, inter-site VPNs, medical IoT | Attackers can move laterally, exfiltrate data or establish persistence without detection; January ransomware and June crypto-miner both went undetected until after damage occurred |
| **G-002** | No network segmentation (VLAN) | Technical Preventive | Entire Central campus (10.10.0.0/16 flat) | Flat network allows compromised workstation or IoT device to access EHR database, billing server or critical infrastructure directly; no containment |
| **G-003** | No Corrective controls for data breach | Administrative Corrective | Patient data (EHR, billing, portal) | No documented procedure to contain breach, notify patients, preserve evidence or coordinate with legal; February portal breach handled informally |
| **G-004** | No business continuity plan (BCP) | Administrative Preventive | Clinical operations (EHR, PACS, monitoring) | Extended power outage beyond 20-minute UPS runtime halts clinical operations with no documented alternative procedures |
| **G-005** | No disaster recovery plan (DRP) | Administrative Corrective | Critical systems (EHR-DB, billing-srv-01, PACS) | Unplanned failure of multiple systems (e.g., ransomware, building fire) has no recovery objective defined; May EHR outage took 9 hours due to untested rollback |
| **G-006** | No camera/monitoring at server room door | Physical Detective | Server room (Central basement) | Unauthorized access to critical infrastructure undetected; January ransomware and June crypto-miner both suggest prior physical or electronic compromise |
| **G-007** | No physical access audit trail | Physical Detective | Server room, network closet, IT offices | Cannot determine who accessed critical infrastructure when; cannot correlate physical access with security incidents |
| **G-008** | No session timeout or screen lock policy | Technical Preventive | All workstations, clinical stations | Task 3 Observation 3: EHR session idle 15+ minutes; unauthorized access to patient records possible; "don't log out" sign actively encourages violation |
| **G-009** | No encryption for data in transit (except VPN) | Technical Preventive | Internal network communications (workstations to servers, medical IoT to EHR) | Vital signs, medications, patient data transmitted over unencrypted internal network; compromised workstation or network access enables data capture |
| **G-010** | No endpoint detection and response (EDR) | Technical Detective | Workstations, clinical endpoints | Crypto-miner and ransomware both evaded detection on billing-srv-01; no behavioral analysis; only signature-based Sophos |
| **G-011** | No security information and event management (SIEM) | Technical Detective | All systems, network, endpoints | No centralized log aggregation; incidents (Jan ransomware, Feb portal breach, Jun crypto-miner) discovered manually or after patient complaint, not by monitoring |
| **G-012** | No vulnerability assessment program | Administrative Preventive | All systems, servers, endpoints | Medical devices (MRI Windows XP, infusion pumps) never formally assessed; unpatched systems unknown; no SLA for remediation |
| **G-013** | No security awareness training | Administrative Preventive | All staff | Intern connected personal laptop to internal network; nurse station leaves EHR open; staff unknown of risks; no baseline security culture |

### Control Gap Pattern Analysis

**Pattern Identified:**
MedDefense's security posture is heavily **Prevention-oriented** (12 preventive vs. 1 detective control). However, the preventive controls themselves are weak and inconsistently applied. **Critical gap: virtually no detection capability.** This means:

1. **Preventive controls fail silently** — compromises occur undetected (ransomware Jan, crypto-miner Jun)
2. **Incident response is reactive, not proactive** — incidents discovered by end-users (portal breach by patient report; dosage error by pharmacist) or months after compromise
3. **No visibility into attackers' presence** — attacker can maintain persistence indefinitely
4. **Investigation is impossible** — no audit logs, no video, no access trails to determine "what happened" after an incident

**Implication:** If an attacker bypasses preventive controls (phishing, supply chain, zero-day), MedDefense has no ability to detect, contain or respond until clinical impact becomes obvious. This is untenable for a healthcare organization handling patient safety data.
