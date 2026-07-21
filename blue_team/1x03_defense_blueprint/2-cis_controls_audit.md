# 2 The CIS Controls Audit

This audit evaluates MedDefense Health Systems against the [Center for Internet Security (CIS) Controls v8](https://www.cisecurity.org/controls) to establish a baseline for technical safeguards.

### Audit Scores by Control

* **CIS Control 1: Inventory and Control of Enterprise Assets**
* **Score:** Partial
* **Evidence:** Active Directory tracking is 8 months out of date, total endpoint counts are unverified (~540 hosts), and rogue devices (`10.10.2.99`) were discovered during vulnerability scanning (1x00, 1x02).
* **CIS Control 2: Inventory and Control of Software Assets**
* **Score:** Partial
* **Evidence:** Software asset tracking is missing across Linux servers and medical IoT devices, allowing unsupported end-of-life operating systems (Ubuntu 18.04, Windows XP) to run in production (1x00, 1x02).
* **CIS Control 3: Data Protection**
* **Score:** Partial
* **Evidence:** Medical imaging data on `pacs-srv-01` is stored unencrypted, and `ehr-db-01` lacks network access control lists to restrict access to patient records (1x00).
* **CIS Control 4: Secure Configuration of Enterprise Assets and Software**
* **Score:** Not Implemented
* **Evidence:** Enterprise assets lack hardening baselines, leaving high-risk misconfigurations such as active Ghostcat RCE on `ehr-srv-01` and LDAP Relay vulnerabilities on Domain Controllers (1x02).
* **CIS Control 5: Account Management**
* **Score:** Partial
* **Evidence:** Active Directory manages individual staff logins, but shared non-attributable credentials like `raduser` are actively used on critical imaging systems (1x00).
* **CIS Control 6: Access Control Management**
* **Score:** Not Implemented
* **Evidence:** Multi-Factor Authentication (MFA) is absent across Active Directory, VPNs, and administrative accounts, with coverage limited to a single personal account (1x00).
* **CIS Control 7: Continuous Vulnerability Management**
* **Score:** Not Implemented
* **Evidence:** MedDefense had no formal vulnerability management process prior to the SecurePoint assessment, resulting in 31 unpatched vulnerabilities across core assets (1x00, 1x02).
* **CIS Control 8: Audit Log Management**
* **Score:** Not Implemented
* **Evidence:** Logs are stored locally, rarely reviewed, and lack centralized collection or SIEM correlation, allowing a crypto-miner to run undetected for weeks (1x00, 1x01).
* **CIS Control 9: Email and Web Browser Protections**
* **Score:** Partial
* **Evidence:** Basic spam filtering is provided via O365 E3, but DNS filtering is unconfigured and the FortiGate firewall permits all outbound egress traffic (1x00).
* **CIS Control 10: Malware Defenses**
* **Score:** Partial
* **Evidence:** Sophos endpoint protection is deployed on Windows workstations, but Linux servers and clinical IoT devices are completely unprotected (1x00).
* **CIS Control 11: Data Recovery**
* **Score:** Partial
* **Evidence:** Automated Veeam backups run daily, but the backup NAS is co-located on the same flat network and rack as production servers with no cloud replication or restore testing (1x00).
* **CIS Control 12: Network Infrastructure Management**
* **Score:** Not Implemented
* **Evidence:** The network runs on a completely flat `/16` subnet without VLAN segmentation, and Westside Clinic relies on an unmanaged consumer Netgear router (1x00).
* **CIS Control 13: Network Monitoring and Defense**
* **Score:** Not Implemented
* **Evidence:** MedDefense maintains no network intrusion detection systems (IDS), intrusion prevention systems (IPS), or continuous traffic flow analysis (1x00, 1x01).
* **CIS Control 14: Security Awareness and Skills Training**
* **Score:** Not Implemented
* **Evidence:** No formal security awareness or anti-phishing training program exists, leading to widespread credential sharing and high susceptibility to social engineering (1x00, 1x01).
* **CIS Control 15: Service Provider Management**
* **Score:** Partial
* **Evidence:** Core vendors like MedTech and Sophos are inventoried with contract costs, but formal third-party cybersecurity risk evaluations are never conducted (1x00).
* **CIS Control 16: Application Software Security**
* **Score:** Not Implemented
* **Evidence:** Web applications like the patient portal (`web-srv-01`) lack secure coding reviews, leading to unpatched access control and remote code execution flaws (1x00, 1x02).
* **CIS Control 17: Incident Response Management**
* **Score:** Not Implemented
* **Evidence:** No documented Incident Response Plan exists, forcing staff to improvise an ad-hoc recovery over 4 days during the January ransomware outbreak (1x00).
* **CIS Control 18: Penetration Testing**
* **Score:** Not Implemented
* **Evidence:** MedDefense has never conducted periodic internal or external penetration tests to validate defensive controls (1x00).

### Scorecard Summary

| Status | Count | Percentage |
| --- | --- | --- |
| **Implemented** | 0 | 0% |
| **Partial** | 7 | 39% |
| **Not Implemented** | 11 | 61% |
| **Total** | **18** | **100%** |

### Top 5 Priority Controls

1. **CIS Control 6: Access Control Management (MFA)**
* **Justification:** Enforcing MFA across Active Directory, administrative logins, and remote access directly neutralizes the primary initial entry vector used by RaaS ransomware actors.

2. **CIS Control 12: Network Infrastructure Management (Segmentation)**
* **Justification:** Implementing VLAN segmentation blocks lateral movement across the flat network, preventing an infection on a workstation from reaching critical EHR servers or legacy medical IoT devices.

3. **CIS Control 7: Continuous Vulnerability Management (Patching)**
* **Justification:** Establishing a routine patch management cadence directly eliminates high-risk exploitation vectors like the Ghostcat RCE on `ehr-srv-01` and SQL injection on `billing-srv-01`.

4. **CIS Control 11: Data Recovery (Isolated Backups)**
* **Justification:** Isolating backup data off-site or in immutable cloud storage ensures MedDefense can recover systems without paying a ransom if production servers are encrypted.

5. **CIS Control 17: Incident Response Management (IR Planning)**
* **Justification:** Developing a tested Incident Response Plan ensures rapid containment during a breach, minimizing clinical downtime and regulatory penalties.
