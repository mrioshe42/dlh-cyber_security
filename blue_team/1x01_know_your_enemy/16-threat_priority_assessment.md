# 16. The Threat Priority Assessment

| Rank | Threat | Actor Type | Primary Vector | Primary Target | Likelihood | Impact | Overall Priority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **1** | **Ransomware-Driven Operational Shutdown** | RaaS Group | Unpatched VPN | EHR Database | Critical | Critical | **Critical** |
| **2** | **Insider Patient Data Exfiltration** | Malicious Insider | Legitimate Access Abuse | EHR Records | High | High | **High** |
| **3** | **Persistent APT Clinical Surveillance** | Nation-State APT | Supply Chain (Firmware) | MRI Workstation | Medium | High | **High** |
| **4** | **Domain-Wide Identity Compromise** | Organized Crime | Phishing / Hash Theft | Active Directory | High | Critical | **High** |
| **5** | **Medical IoT Sabotage** | RaaS Group | Default Credentials | Alaris Pumps | Medium | Critical | **Medium** |

### Top 5 Threat Breakdown

1. **Rank 1: Ransomware-Driven Operational Shutdown**
* **Actor Type**: RaaS Group (e.g., BlackReef).


* **Primary Vector**: Unpatched FortiGate VPN appliance (Net-01).


* **Primary Target**: EHR Database (ehr-db-01).


* **Justification (Likelihood/Impact)**: Healthcare is a primary target for ransomware; MedDefense has unpatched perimeter appliances and no offline backups (Critical/Critical).


* **Key Gap**: Net-04 (Flat network facilitating total environment encryption).


* **Recommended Action**: **Quick Win**: Implement immediate emergency patching for all VPN appliances and initiate network segmentation project.


2. **Rank 2: Insider Patient Data Exfiltration**

* **Actor Type**: Malicious Insider (Billing Employee).


* **Primary Vector**: Abuse of legitimate access/USB.


* **Primary Target**: Patient EHR Records.


* **Justification (Likelihood/Impact)**: High motivation for financial gain during layoffs; no DLP controls (High/High).


* **Key Gap**: SEC-02 (Lack of file integrity monitoring/DLP).


* **Recommended Action**: **Short-term**: Implement technical controls to block USB mass storage and enable auditing/alerting on record export thresholds.


3. **Rank 3: Persistent APT Clinical Surveillance**

* **Actor Type**: Nation-State APT.


* **Primary Vector**: Malicious Vendor Firmware Update.


* **Primary Target**: MRI Workstation (Legacy XP).


* **Justification (Likelihood/Impact)**: State actors frequently target healthcare for long-term espionage; reliance on legacy systems makes detection nearly impossible (Medium/High).


* **Key Gap**: Sys-01 (Use of unsupported OS).


* **Recommended Action**: **Long-term**: Replace or fully isolate legacy XP systems behind strict network access control lists.


4. **Rank 4: Domain-Wide Identity Compromise**

* **Actor Type**: Organized Crime.


* **Primary Vector**: Phishing / LSASS Credential Dumping.


* **Primary Target**: Active Directory (ad-dc-01).


* **Justification (Likelihood/Impact)**: Lack of MFA and weak password policies make credential theft highly probable (High/Critical).


* **Key Gap**: IAM-05 (Lack of privileged account monitoring).


* **Recommended Action**: **Short-term**: Enforce MFA for all domain-joined accounts and move to a tiered administrative access model.


5. **Rank 5: Medical IoT Sabotage**

* **Actor Type**: RaaS Group.


* **Primary Vector**: Default Manufacturer Credentials.


* **Primary Target**: Alaris Medical Pumps.


* **Justification (Likelihood/Impact)**: IoT devices are rarely hardened, allowing physical safety impacts (Medium/Critical).


* **Key Gap**: IAM-04 (Failure to change default credentials).


* **Recommended Action**: **Quick Win**: Audit all clinical IoT devices and enforce secure, unique credentials.


### Strategic Recommendation

If MedDefense could only fund two defensive initiatives in the next quarter, they must prioritize **Network Segmentation (Addressing Net-04)** and **Identity/Privileged Access Management (Addressing IAM-05)**. Network segmentation is the single most effective control to disrupt the lateral movement required for both ransomware encryption and long-term APT persistence, effectively isolating the "crown jewels" (EHR/PACS) from the broader, vulnerable office network. Concurrently, maturing Identity and Access Management—specifically implementing mandatory MFA and strict privileged account monitoring—addresses the root cause of almost every attack path identified, removing the attacker's ability to easily harvest the credentials needed to gain domain-wide control. Together, these initiatives shift MedDefense from a fragile, flat environment to one where an initial compromise is contained and cannot escalate into an organizational catastrophe.
