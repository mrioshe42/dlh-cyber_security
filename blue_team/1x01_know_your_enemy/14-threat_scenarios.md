# 14. The Three Scenarios

### Scenario 1: The "Encrypted Ward" Ransomware Campaign

* **Threat Actor**: Organized Crime / RaaS Group (BlackReef)


* **Motivation**: Financial Gain


* **Initial Vector**: Unpatched FortiGate VPN Appliance (CVE)


* **Attack Surface Exploited**: External

**Attack Sequence**:

* **Step 1**: Initial Access: Exploitation of unpatched CVE on external-facing VPN appliance.


* **Step 2**: Persistence: Deployment of Cobalt Strike beacon as a system service.


* **Step 3**: Discovery: Internal network scanning revealing flat network topology.


* **Step 4**: Privilege Escalation: Kerberoasting the Domain Admin account hash via compromised workstation.


* **Step 5**: Impact: Deployment of ransomware payload via GPO across the entire Windows environment.

**STRIDE Categories Triggered**: Information Disclosure, Denial of Service, Elevation of Privilege
**MedDefense Assets Impacted**: ehr-db-01 (Database), ad-dc-01 (Domain Controller)
**Business Impact**: Total clinical shutdown; 11+ days of downtime; massive loss of patient access to records.
**Gaps Exploited**: Net-01 (Unpatched VPN), Net-04 (Flat network facilitating movement), IAM-05 (Lack of privileged account monitoring).
**Detection Opportunities**: Step 1 (WAF/Intrusion Prevention System flagging exploits), Step 3 (EDR alerting on unauthorized network scanning).

---

### Scenario 2: The "Silent Exit" Insider Exfiltration

* **Threat Actor**: Malicious Insider (Disgruntled Billing Employee)


* **Motivation**: Financial Gain (Selling records)


* **Initial Vector**: Abuse of legitimate EHR/Billing system access


* **Attack Surface Exploited**: Internal


**Attack Sequence**:

* **Step 1**: Discovery: Identifying high-volume record export capabilities in the EHR interface.


* **Step 2**: Collection: Daily extraction of patient data under the guise of work duties.


* **Step 3**: Exfiltration: Moving records via unauthorized physical USB device.


* **Step 4**: Credential Access: Copying plaintext database credentials from a local configuration file.


* **Step 5**: Persistence: Utilizing still-active remote VPN credentials after official employment termination.

**STRIDE Categories Triggered**: Tampering, Repudiation, Information Disclosure
**MedDefense Assets Impacted**: ehr-db-01 (EHR Database), billing-srv-01
**Business Impact**: HIPAA regulatory fines; severe loss of patient trust; legal liability for data breach.
**Gaps Exploited**: SEC-02 (Lack of file integrity monitoring/DLP), IAM-05 (Excessive access permissions), IAM-03 (Failed IT offboarding SLA).
**Detection Opportunities**: Step 2 (DLP system flagging high-volume record exports), Step 3 (Endpoint policy blocking USB mass storage devices).

### Scenario 3: The "Vendor Bridge" Supply Chain Compromise

* **Threat Actor**: Nation-State APT (Vendor Stepping Stone)


* **Motivation**: Espionage / Disruption


* **Initial Vector**: Malicious firmware update pushed through vendor support channel


* **Attack Surface Exploited**: External

**Attack Sequence**:

* **Step 1**: Initial Access: Compromise of MRI workstation via signed, malicious firmware update.


* **Step 2**: Persistence: Rootkit installation on legacy Windows XP operating system.


* **Step 3**: Discovery: Pivot into the clinical network via the flat architecture.


* **Step 4**: Collection: Long-term monitoring and interception of patient diagnostic imaging traffic.


* **Step 5**: Impact: Permanent, stealthy surveillance of clinical operations.

**STRIDE Categories Triggered**: Spoofing, Tampering, Information Disclosure
**MedDefense Assets Impacted**: MRI Workstation, pacs-srv-01
**Business Impact**: Long-term clinical espionage; compromise of diagnostic integrity; severe reputational damage.
**Gaps Exploited**: Sys-01 (Use of unsupported OS), VDR-01 (Lack of vendor audit/supply chain management), Net-04 (Flat network allowing easy lateral movement).
**Detection Opportunities**: Step 1 (Supply chain management/Vendor audit processes), Step 2 (Endpoint isolation/Application allowlisting for legacy systems).
