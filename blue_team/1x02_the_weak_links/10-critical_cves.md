# 10. The Critical CVEs

### 1. Unrestricted PostgreSQL Access (Finding 003)

* **CVE:** None (Misconfiguration)
* **Host:** `billing-srv-01`
* **Asset Role:** Core Billing & Patient Financial Data Storage [1x00 Asset Registry]
* **Asset Criticality:** High (Confidentiality: Critical, Integrity: Critical)
* **Technical Analysis:**
* **Vulnerability Description:** The PostgreSQL service is configured to accept connections from any IP without authentication or via trust-based authentication.
* **CVSS Base Score:** N/A (Estimated 9.8 equivalent due to full data access)
* **Exploit Availability:** High (Tool: `psql`, `metasploit`)
* **CISA KEV Status:** N/A
* **CWE:** CWE-284 (Improper Access Control)
* **Contextual Analysis:**
* **Network Exposure:** Directly accessible from the flat internal network; no segmentation exists.
* **Kill Chain Position:** Actions on Objectives (Data Exfiltration).
* **Threat Actor:** Financial Cybercriminal (would use this to dump billing records).
* **Related Findings:** Finding 006 (MySQL) and Finding 015 (NAS) suggest a pattern of open database services.
* **Adjusted Priority:** **CRITICAL**
* **Justification:** This represents a direct path to the loss of PHI (Protected Health Information). There are no technical barriers between a compromised workstation and the crown jewel of our financial database.

### 2. LDAP Signing Not Required (Finding 007)

* **CVE:** CVE-2017-8563 (Representative reference for domain relay)
* **Host:** `DC-01`
* **Asset Role:** Domain Controller / Identity Provider
* **Asset Criticality:** Very High (Full infrastructure control)
* **Technical Analysis:**
* **Vulnerability Description:** The Domain Controller does not enforce LDAP signing, allowing NTLM relay attacks.
* **CVSS Base Score:** 8.8 (High)
* **Exploit Availability:** High (Tool: `Responder`, `ntlmrelayx`)
* **CISA KEV Status:** Yes (Related to relay vulnerabilities)
* **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
* **Contextual Analysis:**
* **Network Exposure:** Internal, but any internal host can relay requests.
* **Kill Chain Position:** Privilege Escalation / Lateral Movement.
* **Threat Actor:** Advanced Persistent Threat (APT) / Ransomware Operator (to gain Domain Admin).
* **Related Findings:** Finding 019 (RDP enabled) provides the initial access vector to trigger the relay.
* **Adjusted Priority:** **CRITICAL**
* **Justification:** This is the "keys to the kingdom." An attacker who gains a foothold on any endpoint can move laterally to the Domain Controller and seize control of the entire MedDefense network.

### 3. RDP Enabled on Endpoints (Finding 019)

* **CVE:** N/A (Standard configuration risk)
* **Host:** Various Employee Workstations
* **Asset Role:** General Operations
* **Asset Criticality:** Medium
* **Technical Analysis:**
* **Vulnerability Description:** Remote Desktop Protocol is enabled and accessible across the internal network, often using weak credentials or susceptible to credential dumping.
* **CVSS Base Score:** N/A (Estimated 7.5 due to lateral movement utility)
* **Exploit Availability:** High (Tool: `xfreerdp`, `mimikatz`)
* **CISA KEV Status:** N/A
* **CWE:** CWE-287 (Improper Authentication)
* **Contextual Analysis:**
* **Network Exposure:** Lateral access from any compromised node.
* **Kill Chain Position:** Lateral Movement / Persistence.
* **Threat Actor:** Ransomware Operator (typical "living off the land" technique).
* **Related Findings:** Directly enables Finding 007 (LDAP relay) and Finding 004 (Win XP exploitability).
* **Adjusted Priority:** **HIGH**
* **Justification:** RDP is the primary vehicle for ransomware deployment. Once an attacker has one set of credentials, they use RDP to spread horizontally through the organization.

### 4. Windows XP Legacy OS (Finding 004)

* **CVE:** Multiple (e.g., MS17-010 / EternalBlue)
* **Host:** `MRI-01`
* **Asset Role:** Medical Imaging / Patient Diagnostics
* **Asset Criticality:** Critical (Patient Safety / Availability)
* **Technical Analysis:**
* **Vulnerability Description:** System runs Windows XP, which is end-of-life and unsupported. It contains numerous unpatchable kernel vulnerabilities.
* **CVSS Base Score:** 10.0 (Critical)
* **Exploit Availability:** High (Metasploit `ms17_010_eternalblue`)
* **CISA KEV Status:** Yes
* **CWE:** CWE-1188 (Insecure Default Initialization)
* **Contextual Analysis:**
* **Network Exposure:** Network-isolated (or should be), but currently on the flat network.
* **Kill Chain Position:** Delivery / Exploitation.
* **Threat Actor:** Opportunistic botnet or Ransomware (targeting imaging devices).
* **Related Findings:** Finding 016 (Medical device interface access).
* **Adjusted Priority:** **CRITICAL**
* **Justification:** This is an unfixable vulnerability. As long as this machine is on the network, it is a guaranteed exploit path. The risk here is not just data, but patient safety if the MRI service is disrupted.

### 5. MySQL Bound to 0.0.0.0 (Finding 006)

* **CVE:** N/A (Misconfiguration)
* **Host:** `web-srv-01`
* **Asset Role:** Patient Portal/Billing Web Frontend
* **Asset Criticality:** High
* **Technical Analysis:**
* **Vulnerability Description:** The MySQL service is listening on all interfaces (`0.0.0.0`), including the public-facing side, exposing the database port to anyone.
* **CVSS Base Score:** N/A (Estimated 9.0)
* **Exploit Availability:** High
* **CISA KEV Status:** N/A
* **CWE:** CWE-200 (Exposure of Sensitive Information)
* **Contextual Analysis:**
* **Network Exposure:** High (Exposed to the internet/DMZ).
* **Kill Chain Position:** Delivery / Weaponization.
* **Threat Actor:** Script Kiddie or Automated Scanners (searching for open DBs).
* **Related Findings:** Finding 003 (PostgreSQL) is the internal equivalent.
* **Adjusted Priority:** **HIGH**
* **Justification:** This is an open door to the internet. We are essentially inviting automated scanners to brute-force our patient database.
