# 3 The Gap-to-Framework Bridge

Connecting technical gaps, vulnerabilities, and threat vectors to security frameworks translates raw operational security findings into a structured, board-defensible strategy. By establishing this traceability chain (**Gap → Vulnerability → Threat → Framework Control → Recommended Action**), security investments move from "recommended best practices" to quantitative risk-reduction controls directly tied to mitigating threat scenarios.

### High-Priority Framework Bridge Mappings

#### 1. Network Architecture & Segmentation

* **Gap Reference:** GAP-001 (Net-04)
* **Description:** Unsegmented flat network architecture (`10.10.0.0/16`) allowing unrestricted lateral movement across medical IoT, clinical database servers, and general workstations.
* **Vulnerability Evidence:** Finding 003 (PostgreSQL unrestricted access), Finding 010 (Alaris Pump unauthenticated/unsegmented access), Finding 016 (Philips Monitor unauthenticated data stream access).
* **Threat Context:** RaaS Groups / Organized Crime (Kill Chain #1: Ransomware Lateral Movement & Mass Encryption).
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 12: Network Infrastructure Management
* **Recommended Action:** Implement 802.1Q VLAN segmentation and firewall microsegmentation to isolate clinical IoT devices, legacy operating systems, and core database servers from general workstation traffic.

#### 2. Logging, Detection, & Traffic Monitoring

* **Gap Reference:** GAP-002
* **Description:** Absence of centralized audit logging (SIEM) and network intrusion detection systems (IDS/NIDS), leaving internal traffic unmonitored.
* **Vulnerability Evidence:** Finding 007 (LDAP Relay vulnerability on DC-01), Finding 031 (Ghostcat RCE on `web-srv-01`), Undetected crypto-miner on `billing-srv-01`.
* **Threat Context:** RaaS Groups & Opportunistic Attackers (Kill Chain #1 & #2: Undetected Persistence, Reconnaissance, and Data Exfiltration).
* **NIST CSF Function:** Detect (DE)
* **CIS Control:** CIS Control 8: Audit Log Management & CIS Control 13: Network Monitoring and Defense
* **Recommended Action:** Deploy a centralized SIEM and network intrusion detection sensors to continuously aggregate logs and monitor east-west network traffic for anomalous behavior.

#### 3. Legacy & End-of-Life Systems Protection

* **Gap Reference:** GAP-009 (Sys-01)
* **Description:** End-of-Life Windows XP Embedded operating system running on the Siemens MRI scanner without compensating network or host controls.
* **Vulnerability Evidence:** Legacy EOL System Findings (Windows XP Embedded on MRI, Server 2012, unpatched legacy drivers).
* **Threat Context:** Nation-State Actors (APT) & RaaS Groups (Kill Chain #5: Persistent Foothold and Exploitation via Legacy Infrastructure).
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 4: Secure Configuration of Enterprise Assets and Software
* **Recommended Action:** Isolate the unsupported Windows XP MRI system behind an inline network micro-firewall that restricts incoming and outgoing traffic strictly to authorized PACS destinations.

#### 4. Data Protection & Encryption at Rest

* **Gap Reference:** GAP-003
* **Description:** Unencrypted databases storing high-value Electronic Health Records (EHR), billing records, and PACS diagnostic imaging files at rest.
* **Vulnerability Evidence:** Finding 003 (SQL Injection on `billing-srv-01`), unencrypted storage volumes on `ehr-db-01` and `pacs-srv-01`.
* **Threat Context:** RaaS Groups & Malicious Insiders (Kill Chain #1 & #3: Double Extortion Data Exfiltration and Direct Theft).
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 3: Data Protection
* **Recommended Action:** Implement AES-256 database-at-rest encryption across EHR, Billing, and PACS data stores while enforcing strict column-level access controls.

#### 5. Identity, Access Control, & Authentication

* **Gap Reference:** GAP-008 (IAM-05)
* **Description:** Absence of Multi-Factor Authentication (MFA) and widespread deployment of non-attributable shared accounts across critical clinical systems.
* **Vulnerability Evidence:** Finding 007 (LDAP Relay / Domain Takeover vector), active shared `raduser` credentials on PACS imaging infrastructure.
* **Threat Context:** RaaS Groups & Negligent Insiders (Kill Chain #1 & #3: Credential Harvesting, Privilege Abuse, and Escalation).
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 6: Access Control Management
* **Recommended Action:** Mandate Multi-Factor Authentication across Active Directory logins, VPN endpoints, and administrative portals while replacing shared accounts with unique, attributable credentials.

#### 6. Incident Response & Preparedness

* **Gap Reference:** GAP-006
* **Description:** Complete absence of a documented Incident Response (IR) Plan and formal playbooks, resulting in uncoordinated and prolonged recovery operations.
* **Vulnerability Evidence:** 4-day ad-hoc recovery timeline during the January ransomware outbreak, unmanaged crypto-miner execution on `billing-srv-01`.
* **Threat Context:** RaaS Groups & Opportunistic Attackers (Kill Chain #1: Delayed Containment and High Operational Recovery Downtime).
* **NIST CSF Function:** Respond (RS)
* **CIS Control:** CIS Control 17: Incident Response Management
* **Recommended Action:** Formulate and regularly test a formal Incident Response Plan with explicit playbooks for ransomware containment, breach notification, and forensic evidence preservation.

#### 7. Data Recovery & Backup Architecture

* **Gap Reference:** GAP-007
* **Description:** Lack of immutable or off-site backups, exposing local backup repositories co-located on the flat network to ransomware encryption.
* **Vulnerability Evidence:** Co-located Veeam backup NAS (`backup-srv-01`) on the primary subnet with zero cloud replication or write-once immutability.
* **Threat Context:** RaaS Groups (Kill Chain #1: Pre-encryption Backup Destruction to Force Ransom Payment).
* **NIST CSF Function:** Recover (RC)
* **CIS Control:** CIS Control 11: Data Recovery
* **Recommended Action:** Rearchitect backup infrastructure to enforce the 3-2-1 rule with air-gapped or immutable cloud storage and perform mandatory semi-annual restoration drills.

#### 8. Perimeter Hardening & Edge Management

* **Gap Reference:** GAP-004 (Net-01)
* **Description:** Unmanaged consumer network hardware deployed at remote clinics and unpatched internet-facing web application services.
* **Vulnerability Evidence:** Finding 031 (Ghostcat RCE on `web-srv-01`), unmanaged Netgear Nighthawk consumer router deployed at Westside Clinic.
* **Threat Context:** Opportunistic Attackers & Initial Access Brokers (Kill Chain #1: External Perimeter Exploitation and Initial Network Entry).
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 4: Secure Configuration of Enterprise Assets and Software
* **Recommended Action:** Replace consumer-grade equipment with enterprise managed firewalls at remote clinics and establish a emergency patching process for internet-facing assets within 48 hours of vulnerability disclosure.

### Traceability Summary Table

| Gap Reference | Description | Vulnerability Evidence | Threat Context | NIST CSF Function | CIS Control | Recommended Action |
| --- | --- | --- | --- | --- | --- | --- |
| **GAP-001 (Net-04)** | Flat network architecture with no internal segmentation | Finding 003, 010, 016 | RaaS Groups (Kill Chain #1: Lateral Movement) | Protect (PR) | CIS Control 12 (Network Infrastructure Management) | Deploy 802.1Q VLANs and firewall microsegmentation for IoT, legacy OS, and DB servers. |
| **GAP-002** | Missing SIEM and network intrusion detection (IDS) | Finding 007, 031, Crypto-miner | RaaS Groups & Opportunistic (Kill Chain #1 & #2: Persistence) | Detect (DE) | CIS Control 8 (Audit Log) & CIS Control 13 (Network Defense) | Deploy a central SIEM and NIDS sensors to log and monitor east-west network traffic. |
| **GAP-009 (Sys-01)** | EOL Windows XP Embedded on MRI without compensating controls | Legacy EOL Findings | Nation-State & RaaS (Kill Chain #5: Persistent Foothold) | Protect (PR) | CIS Control 4 (Secure Configuration) | Isolate Windows XP MRI scanner behind an inline hardware micro-firewall. |
| **GAP-003** | Unencrypted core databases (EHR, Billing, PACS) at rest | Finding 003, unencrypted volumes | RaaS & Insiders (Kill Chain #1 & #3: Data Exfiltration) | Protect (PR) | CIS Control 3 (Data Protection) | Implement AES-256 database-at-rest encryption across EHR, Billing, and PACS stores. |
| **GAP-008 (IAM-05)** | Lack of MFA and shared accounts on critical systems | Finding 007, shared `raduser` | RaaS & Insiders (Kill Chain #1 & #3: Privilege Abuse) | Protect (PR) | CIS Control 6 (Access Control Management) | Mandate MFA for Active Directory/VPN and phase out shared user credentials. |
| **GAP-006** | No documented Incident Response Plan or playbooks | 4-day recovery timeline, Crypto-miner | RaaS & Opportunistic (Kill Chain #1: Uncontrolled Breach) | Respond (RS) | CIS Control 17 (Incident Response Management) | Establish a formal IR Plan with specific playbooks for ransomware containment and recovery. |
| **GAP-007** | Non-immutable co-located backup architecture | Backup NAS on flat network | RaaS Groups (Kill Chain #1: Backup Destruction) | Recover (RC) | CIS Control 11 (Data Recovery) | Transition to a 3-2-1 backup model with immutable cloud storage and regular restoration drills. |
| **GAP-004 (Net-01)** | Unmanaged remote clinic hardware & unpatched perimeter | Finding 031, Netgear router | Initial Access Brokers & Opportunistic (Kill Chain #1: Entry) | Protect (PR) | CIS Control 4 (Secure Configuration) | Replace consumer routers with enterprise firewalls and institute 48-hour emergency patching. |
