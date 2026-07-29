## 2. The Kill Chain Overlay

### Part 1 - The Overlay

| Kill Chain #1 (Ransomware Encrypts EHR) Step | Crimson Tide Attack Chain Phase | Match / Divergence Analysis |
| --- | --- | --- |
| **Step 1: Initial Access** *(VPN Exploit)* | **Phase 1: Initial Access** *(Perimeter / Remote Asset Exploitation)* | **Match:** Both models correctly anticipate that perimeter exploitation via unpatched vulnerabilities (such as the FortiGate VPN appliance) serves as the primary entry point. |
| **Step 2: Establish Foothold** *(Cobalt Strike beacon)* | **Phase 2: Execution & Persistence** *(Scheduled tasks / compromised credentials)* | **Match with Nuance:** Both models identify the immediate need for a post-compromise foothold. While Kill Chain #1 specifically notes a Cobalt Strike beacon due to lack of EDR, Crimson Tide utilizes native tasks and credentials to achieve the same persistent foothold. |
| **Step 3: Lateral Movement / Escalation** *(Flat network pivot)* | **Phase 3 & 5: Privilege Escalation & Lateral Movement** | **Match:** Both models rely heavily on MedDefense's flat internal network and weak directory controls (such as LDAP relay or default credentials) to escalate privileges to domain admin and pivot across subnets. |
| **Step 4: Objective Execution** *(Ransomware via GPO)* | **Phase 7: Impact / Ransomware Deployment** | **Match:** Both target core infrastructure and backup repositories to paralyze operations and maximize extortion leverage. |
| **Step 5: Impact** *(Clinical downtime / Data loss)* | **Phase 6 & 7: Data Exfiltration & Impact** | **Divergence:** While Kill Chain #1 focuses primarily on availability loss (ransomware encryption), Crimson Tide's real-world playbook explicitly incorporates a dual-extortion phase (Phase 6: Data Exfiltration) prior to encryption, adding a severe regulatory and confidentiality breach dimension that was underemphasized in the baseline model. |

### Part 2 - Control Interception Map

| Phase | Planned Control [from 1x03] | Status [Funded/Not Deployed, Deployed, Not Funded] | Would It Stop This Phase? [Yes/Partially/No] |
| --- | --- | --- | --- |
| **Phase 1 (Initial Access)** | Control 1 / Control 6 (FortiGate Enterprise Firewall & Patching) | Funded | **Yes** (Provided patching is applied or virtual patching/WAF rules block CVE-2023-27997). |
| **Phase 2 (Execution & Persistence)** | Control 5 (Sophos Intercept X EDR Upgrade) | Funded | **Yes** (Behavioral monitoring detects and blocks unauthorized beacon execution or persistence mechanisms). |
| **Phase 3 (Privilege Escalation)** | Control 2 (MFA Deployment & Identity Hardening) | Funded | **Yes** (Blocks credential relay and unauthorized domain admin escalation paths). |
| **Phase 4 (Defense Evasion)** | Control 3 (Wazuh Open-Source SIEM) | Funded | **Partially** (Will generate alerts, but without a 24/7 Managed SOC [Control 7 - Not Funded], off-hours evasion windows remain viable). |
| **Phase 5 (Lateral Movement)** | Control 1 (Zero-Trust Network Segmentation / VLANs) | Funded | **Yes** (Isolates clinical and database subnets, breaking the east-west pivot path). |
| **Phase 6 (Data Exfiltration)** | Control 3 & 6 (SIEM Logging & Egress Filtering) | Funded | **Partially** (Stops unmonitored bulk data flows, though low-and-slow exfiltration may bypass basic alerting thresholds without 24/7 analysis). |
| **Phase 7 (Impact / Ransomware)** | Control 4 (Offsite Immutable Backups via AWS Glacier) | Funded | **Yes** (Guarantees recovery within 48 hours without paying ransom, neutralizing the availability impact). |

### Part 3 - The Gap Between Plan and Reality

If MedDefense had fully implemented the funded Security Strategy from 1x03, **6 out of the 7** Crimson Tide phases would be actively blocked or severely disrupted, while **1 phase** (Phase 4 / Defense Evasion or low-and-slow exfiltration) could potentially maintain partial success due to deferred 24/7 monitoring. This tells us that even after full implementation of a robust $120k baseline security strategy, **residual risk cannot be reduced to zero**; tactical controls create significant friction and containment boundaries, but sophisticated threat actors can still exploit blind spots in human-dependent log reviews or unmonitored off-hours dwell windows, necessitating continuous threat-informed adaptation and future managed detection investments.
