# 13. The Quick Wins

## Quick Wins Strategy (First 14 Days)

While the comprehensive six-month security roadmap matures, these five high-impact, low-friction quick wins leverage existing software entitlements, administrative policies, and system settings. They require **no additional budget approval** and can be deployed within two weeks to disrupt critical attack pathways.

### Quick Win #1: Disable Legacy Protocol Authentication & Force MFA on M365

* **Risk Addressed:** `RISK-001` (Ransomware EHR Encryption) & `RISK-002` (PHI Data Exfiltration)
* **Action:**
1. Access the Microsoft Entra ID (Azure AD) Admin Center.
2. Create a Conditional Access Policy enforcing Multi-Factor Authentication (MFA) for all administrative and clinical users accessing M365.
3. Create a secondary Conditional Access Policy that explicitly blocks Legacy Authentication protocols (IMAP, POP3, SMTP, and basic auth) across all tenant accounts.
4. Enable system alert notifications for suspicious login attempts and MFA bypass attempts.


* **Owner:** IT Director (Sarah Park)
* **Timeline:** Days 1–3 (72 Hours)
* **Cost:** **$0** (Included in existing Microsoft 365 E3 licenses)
* **Risk Reduction:** Disrupts the **Initial Access** stage of the ransomware kill chain by neutralizing automated password-spraying and credential-stuffing attacks that exploit legacy un-MFA'd protocols.
* **Verification:** Run `Get-EntraIDUserDetail` via PowerShell to confirm 100% MFA enrollment; execute test logins using IMAP/POP3 to verify connections are blocked.

### Quick Win #2: Quarantine and Re-bind the Radiology Shared Account (`raduser`)

* **Risk Addressed:** `RISK-009` (Shared Administrative Credential Misuse)
* **Action:**
1. Audit Active Directory for all active sessions, group memberships, and mapped permissions assigned to `raduser`.
2. Provision unique Active Directory user accounts for each radiology staff member using the standardized naming convention (`first.last@meddefense.org`).
3. Re-map local Radiology workstation and PACS application permissions to individual user accounts.
4. Disable the `raduser` account in Active Directory and reset its password to a random 64-character string held in the IT password vault.


* **Owner:** IT Operations / IAM Lead
* **Timeline:** Days 4–6 (72 Hours)
* **Cost:** **$0** (Internal administrative configuration labor)
* **Risk Reduction:** Disrupts the **Privilege Escalation** and **Lateral Movement** kill chain phases by enforcing non-repudiation and eliminating unmonitored shared administrative access across imaging assets.
* **Verification:** Review Active Directory authentication logs to confirm zero login attempts under `raduser` and verify radiology staff successfully log in via individual credentials.

### Quick Win #3: Power Down, Disconnect, and Audit Shadow IT Hardware

* **Risk Addressed:** `RISK-006` (Branch Perimeter Compromise) & `RISK-007` (Lack of Centralized Threat Visibility)
* **Action:**
1. Physically locate and power down the unmonitored Raspberry Pi network capture appliance (`A-040`) on the 2nd-floor network closet; secure its SD card for IT inventory review.
2. Perform an inventory scan on Dr. Patel's personal NAS (`A-038`); copy Cardiology research data to the managed, encrypted corporate NAS, and remove the unmanaged hardware from the switch port.
3. Close personal Google Drive sharing settings for Marketing files (`A-039`) and migrate data to Microsoft Teams/SharePoint.
4. Issue a formal IT notification reminding staff of the AUP ban on unauthorized hardware.


* **Owner:** Infrastructure Lead & Deputy CISO (James Chen)
* **Timeline:** Days 7–9 (72 Hours)
* **Cost:** **$0** (Internal labor and existing managed storage capacity)
* **Risk Reduction:** Eliminates unmonitored persistence vectors and unauthorized data exfiltration channels, severing potential **Command and Control (C2)** pivot points used by internal or external actors.
* **Verification:** Conduct an automated nmap/subnet scan across the local LAN and verify no unmanaged IP addresses or MAC addresses respond on clinical subnets.

### Quick Win #4: Block USB Mass Storage via Group Policy (GPO) & Sophos

* **Risk Addressed:** `RISK-003` (Negligent Insider Data Leakage & USB Malware)
* **Action:**
1. Open Active Directory Group Policy Management Console (GPMC).
2. Configure a domain-wide Group Policy Object (GPO) under `Computer Configuration -> Administrative Templates -> System -> Removable Storage Access` setting "All Removable Storage classes: Deny all access" to **Enabled**.
3. Apply the policy across all 280 clinical and administrative workstation Organizational Units (OUs).
4. Update the Sophos endpoint policy central console to enforce peripheral control blocking for unapproved USB mass storage devices.


* **Owner:** Endpoint Administrator
* **Timeline:** Days 10–11 (48 Hours)
* **Cost:** **$0** (Uses built-in Windows GPO and existing Sophos EDR platform)
* **Risk Reduction:** Disrupts the **Execution** and **Exfiltration** kill chain steps by blocking physical USB malware drops (e.g., Rubber Ducky payloads) and preventing unauthorized downloading of PHI onto personal flash drives.
* **Verification:** Insert a test USB flash drive into three random clinical workstations across different OUs to confirm access is explicitly denied by both Windows GPO and Sophos.

### Quick Win #5: Enable & Verify AWS S3 Object Lock on Offsite Backup Buckets

* **Risk Addressed:** `RISK-008` (Ransomware Permanent Data Destruction)
* **Action:**
1. Log into the AWS Management Console and navigate to S3 Storage settings for the MedDefense backup destination bucket.
2. Enable **S3 Object Lock** in Compliance Mode with a default retention period of 30 days.
3. Update the local Veeam backup server job configuration to attach the immutability flag on all outbound offsite replication jobs.
4. Initiate a manual test backup run to verify immutable flag tagging in AWS S3.


* **Owner:** Backup & Storage Lead
* **Timeline:** Days 12–14 (48 Hours)
* **Cost:** **$0** (Minimal standard S3 storage API transaction fees covered under existing AWS allocation)
* **Risk Reduction:** Neutralizes the adversary's **Actions on Objectives** phase during ransomware attacks, preventing attackers from deleting or encrypting offsite backups even if domain administrator credentials are compromised.
* **Verification:** Attempt to manually delete a test backup file from the AWS S3 bucket via the AWS CLI using administrative credentials, confirming the API returns an `AccessDenied / ObjectLock` error.

### Organizational Value of Quick Wins

Beyond immediate risk reduction, quick wins play a vital strategic role during the first month of a security transformation. They demonstrate operational momentum and tangible capability to the Board of Directors before major capital expenditures begin, building crucial executive trust and credibility for CISO leadership. Internally, quick wins create a sense of momentum among technical staff, proving that meaningful security posture improvements can be achieved rapidly without waiting for lengthy procurement cycles. Finally, by eliminating easy entry vectors early, the security team stabilizes the baseline environment, giving leadership the breathing room necessary to execute complex, long-term engineering projects—such as full network segmentation and enterprise SIEM integration—without suffering preventable incidents in the interim.
