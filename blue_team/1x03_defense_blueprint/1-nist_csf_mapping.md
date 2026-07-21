# 1 The NIST CSF Mapping

MedDefense's posture has been mapped against the [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) six core functions based on findings from Projects 0x00, 0x01, and 0x02.

### Function 1: Govern (GV)

* **Current Level:** Partial
* **Evidence:** CISO position is vacant; security authority is split between James Chen (policy) and Sarah Park (IT ops); no formal security policies (AUP/IR) exist; HIPAA compliance was never formally audited.
* **Key Gaps:** Lack of documented security policy hierarchy, missing risk management strategy, and split authority between IT and security.
* **Target Level:** **Managed** — Establish core security policies (AUP, IR), define RACI governance roles, and align strategic risk management with Board reporting.

### Function 2: Identify (ID)

* **Current Level:** Partial
* **Evidence:** Prior to Project 0x00, no central asset inventory existed (AD list was 8 months out of date); 31 vulnerabilities identified in 0x02; shadow IT (`10.10.2.99`) and unmapped EOL OS (Windows XP, Ubuntu 18.04) were discovered during scanning.
* **Key Gaps:** Incomplete asset lifecycle tracking and lack of an active, quantitative enterprise Risk Register.
* **Target Level:** **Managed** — Maintain automated asset discovery, formalize hardware/software inventories, and maintain a quantitative Risk Register.

### Function 3: Protect (PR)

* **Current Level:** Partial
* **Evidence:** Flat `/16` network allows unrestricted lateral movement; MFA is deployed on only 1 personal account; 31 vulnerabilities found including Ghostcat RCE on `ehr-srv-01`; Sophos endpoint protection lacks Linux/server coverage.
* **Key Gaps:** Unsegmented network architecture putting clinical IoT at risk, missing MFA on Domain Controllers (`ad-dc-01`), and unpatched critical RCE/SQLi flaws.
* **Target Level:** **Managed** — Enforce network segmentation (VLANs), mandate MFA across all endpoints/AD, and establish a monthly patch management SLA.

### Function 4: Detect (DE)

* **Current Level:** Not Implemented
* **Evidence:** Zero SIEM or centralized log aggregation; a crypto-miner ran undetected on `billing-srv-01` for weeks; firewall and host logs are rarely reviewed; no 24/7 network monitoring capability exists.
* **Key Gaps:** Complete absence of real-time event monitoring, log correlation, and threat detection mechanisms.
* **Target Level:** **Partial** — Deploy centralized log collection/SIEM for critical servers and domain controllers with automated alert rules for high-severity anomalies.

### Function 5: Respond (RS)

* **Current Level:** Partial
* **Evidence:** The January ransomware incident was handled ad-hoc over 4 days; no formal Incident Response Plan (IRP) exists; no containment procedures or breach notification workflows are defined.
* **Key Gaps:** Lack of a documented, tested Incident Response Plan and standardized triage playbooks.
* **Target Level:** **Managed** — Author and test a formal IRP, establish containment protocols, and define regulatory breach communication procedures.

### Function 6: Recover (RC)

* **Current Level:** Partial
* **Evidence:** Backup NAS (`backup-srv-01`) is co-located in the same server room, rack, and network as production systems with no cloud replication; backup restore procedures have never been tested; RTO/RPO metrics are undefined.
* **Key Gaps:** Co-located, non-isolated backup infrastructure representing a single point of failure during a ransomware event.
* **Target Level:** **Managed** — Implement immutable, air-gapped/cloud-replicated backups and conduct quarterly restore testing to guarantee a 4-hour RTO for critical clinical EHR data.
