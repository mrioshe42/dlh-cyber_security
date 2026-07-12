# 13: The Reality Check

## Breach Analysis: Real-World Correlations to MedDefense

### **BREACH 1: Regional Hospital Alpha — Ransomware via Unpatched VPN (Q3 2023)**

**Attack Vector Identification:**
- **Initial Entry Point:** VPN appliance with known, unpatched CVE (patch available 4 months prior, not applied)
- **Lateral Movement:** Flat internal network; attacker reached AD domain controller in 3 hours
- **Payload:** Ransomware deployed via Group Policy using compromised domain admin account; encrypted 23 servers + 400 workstations; EHR, billing, imaging affected
- **Data Exposure:** Unknown patient records potentially exfiltrated before encryption
- **Detection:** Zero alerts during 3-hour reconnaissance; no network monitoring
- **Backup Failure:** NAS on same network; ransomware encrypted backups and production simultaneously; most recent viable backup 5 weeks old
- **Impact:** 11 days EHR downtime, $5M total loss, regulatory investigation, CEO resignation

**MedDefense Correlation (Identified Gaps):**
- **GAP-001:** Medical IoT segmentation — MedDefense has flat network (10.10.0.0/16); attacker would reach infusion pumps, patient monitors, MRI in minutes
- **GAP-002:** SIEM/network detection — MedDefense has zero network monitoring; 3-hour lateral movement would be invisible
- **GAP-006:** Incident response plan — MedDefense has ad-hoc IR; response would be improvised (as occurred in January ransomware incident, Exercise 2)
- **GAP-007:** Business continuity/DRP — MedDefense has no BCP; EHR outage would force ambulance diversion
- **C-006 (Weak Control):** Backup system — MedDefense backups stored on NAS in same rack as production; ransomware affects both (identical to Breach 1 failure)

**New Gaps Identified (NOT in MedDefense Analysis):**
- **GAP-012 (NEW): Perimeter Device Patch Management** — MedDefense does NOT have documented patch management for FortiGate firewall, Netgear router (Westside VPN endpoint), or network appliances. Vendor advisories unknown; patch schedule unknown; critical vulnerability risk identical to Breach 1.
  - **Severity:** CRITICAL — Westside Netgear router has no firewall and carries site-to-site VPN; unpatched VPN vulnerability = direct access to all MedDefense systems
  - **Evidence:** Network scan shows Westside equipment firmware unknown; no IT documentation of patch procedures

**Blind Spot Check:** ✓ **COVERED BY EXISTING GAPS** — The flat network (GAP-001), lack of detection (GAP-002), and backup co-location (C-006 weakness) would enable identical ransomware scenario at MedDefense.

### **BREACH 2: Health Network Beta — Insider Threat via Retained Credentials (Q1 2024)**

**Attack Vector Identification:**
- **Initial Access:** Former billing employee retained active VPN and EHR credentials for 47 days after termination
- **Why Access Persisted:** Offboarding process required manager to submit manual ticket to IT; manager forgot; no automated deactivation
- **Exploitation:** 14 remote accesses over 6 weeks; downloaded 3,211 patient records (names, DOB, SSN, insurance, diagnosis codes)
- **Detection Failure:** No MFA (attacker used original username/password); access logs existed but were NEVER REVIEWED; no behavioral analytics (off-hours access, unusual source IP); no DLP on export
- **Discovery:** Only detected when patient called after receiving fraudulent medical bill
- **Impact:** 3,211 patients notified, $890K response costs, class action lawsuit, regulatory investigation

**MedDefense Correlation (Identified Gaps):**
- **GAP-004:** Password policy inadequate (no MFA except James Chen's personal account) — MedDefense has 8-char/90-day policy but NO MFA on VPN, EHR, or remote access; identical to Breach 2
- **C-004 (Weak Control):** Active Directory has no MFA; shared accounts (PACS "raduser") bypass access controls; no behavioral monitoring
- **C-019 (Weak Control):** Logging exists (FortiGate, Linux syslog) but no centralized log review; logs without review = security theater (as Breach 2 demonstrates)

**New Gaps Identified (NOT in MedDefense Analysis):**
- **GAP-013 (NEW): MFA on All Remote Access** — MedDefense does NOT require MFA on VPN or remote EHR access. Only James Chen has personal MFA. Identical to Breach 2 failure.
  - **Severity:** CRITICAL — Westside and HQ staff connect via VPN; remote laptops (~30 units) access EHR via VPN; former employee scenario would replicate at MedDefense with same outcome
  - **Evidence:** Exercise 4 Control C-004 notes "MFA recommended but not required"; no technical control enforcement

- **GAP-014 (NEW): Automated Account Offboarding / Lifecycle Management** — MedDefense has no automated deactivation linked to HR termination. Offboarding depends on manual manager action (same failure as Breach 2).
  - **Severity:** CRITICAL — 2,000 MedDefense staff; high turnover in clinical roles; any departing employee could retain access for weeks
  - **Evidence:** Onboarding packet shows no IT-HR integration; no documented offboarding procedure; manual ticket-based process

- **GAP-015 (NEW): Log Review / Audit Monitoring** — MedDefense logs exist but are never reviewed. Behavioral anomalies (off-hours access, unusual volumes) would not be detected.
  - **Severity:** CRITICAL — Exercise 4, Artifact 8 states "Windows servers... if something breaks" and "only time we look at AD logs is when something breaks"; no continuous monitoring
  - **Evidence:** Breach 2 had audit trail; nobody examined it until forensics; MedDefense has identical gap

- **GAP-016 (NEW): Data Loss Prevention (DLP) on Sensitive Data** — MedDefense has no DLP controls on EHR data export. Former employee scenario (downloading 3,211 records) would go undetected.
  - **Severity:** CRITICAL — 50,000 patient records in EHR; any employee could export to USB/email without alert
  - **Evidence:** Exercise 9 data map shows no DLP mentioned; no export restrictions documented

**Blind Spot Check:** ✓ **NEWLY IDENTIFIED GAPS** — These four gaps (MFA, automated offboarding, log review, DLP) were NOT in the original Exercise 12 gap analysis but are CRITICAL per Breach 2 evidence.

### **BREACH 3: Community Hospital Gamma — Medical Device Pivot via Portal Vulnerability (Q4 2024)**

**Attack Vector Identification:**
- **Initial Access:** Patient portal with unpatched web application vulnerability (patch available 2 months prior)
- **DMZ Misconfiguration:** DMZ allowed outbound connections to internal network (for "application functionality"); defeated DMZ purpose
- **Lateral Movement:** From portal, attacker discovered medical IoT (patient monitors, infusion pumps) on same network as workstations/servers
- **Medical Device Exploitation:** Infusion pump management interface accessible with default credentials (admin/admin, never changed); contained patient names and medication dosages
- **Secondary Payload:** Cryptocurrency mining installed on portal server and 3 clinical workstations
- **Detection:** ONLY detected by biomedical technician noticing unusual traffic manually 23 days after compromise
- **Network Monitoring Gap:** No automated detection; manual observation was sole detection method
- **Impact:** 800 patients' data exposed, crypto-mining degraded clinical workstation performance, $600K total response + remediation costs, FDA notification required, medical device isolation project forced

**MedDefense Correlation (Identified Gaps):**
- **GAP-001:** Medical IoT segmentation — MedDefense has flat network; patient monitors, infusion pumps, MRI on same network as workstations; identical to Breach 3 failure; attacker reaches life-safety devices in seconds
- **C-010 (Adequate Control):** Web server DMZ placement — appears adequate but...
- **GAP-002:** Network detection — MedDefense has zero network monitoring; 23-day dwell time would go undetected; only manual observation caught Breach 3 (same as MedDefense's detection capability: none)
- **C-003 (Weak Control):** Sophos antivirus does not cover servers or Linux; crypto-miner on portal or clinical workstation would bypass detection

**New Gaps Identified (NOT in MedDefense Analysis):**
- **GAP-017 (NEW): DMZ Misconfiguration (Outbound to Internal)** — MedDefense firewall rules (C-001, Exercise 4, Artifact 1) allow "ALL outbound" from internal to internet. Reverse risk exists: does DMZ allow outbound to internal for "application functionality"?
  - **Severity:** HIGH — If web-srv-01 (DMZ) requires outbound to internal for billing integration or EHR queries, attacker on web-srv-01 can pivot to internal servers
  - **Evidence:** Exercise 4, Artifact 1 shows firewall rules permit "Allow-Internal-Outbound (ALL services)"; no mention of DMZ-to-internal restrictions

- **GAP-018 (NEW): Default Credentials on Medical Devices** — MedDefense does NOT have documented credential management for medical device management interfaces (patient monitors, infusion pumps, badge readers, MRI).
  - **Severity:** CRITICAL — Breach 3 accessed infusion pump console with default admin/admin; MedDefense has ~200 medical devices; default credentials on any device = open door
  - **Evidence:** Exercise 7 Network Scan shows Philips monitors (HTTP/HTTPS on ports 80/443), BD Alaris pumps (80/443), badge readers, MRI; no credential management documented; vendor defaults likely unchanged

- **GAP-019 (NEW): Medical Device Firmware Vulnerability Management** — MedDefense does NOT have program for monitoring/remediating medical device firmware vulnerabilities.
  - **Severity:** CRITICAL — Exercise 7 notes BD Alaris firmware v12.1.2 has known CVEs (BD security bulletin 18 months ago); network isolation recommended but not implemented; no firmware update process documented
  - **Evidence:** Network scan detects BD Alaris fw 12.1.2 (identified version); no firmware baseline or patch schedule; Exercise 6 addressed Windows XP MRI (can't patch) but not proactive firmware management for other devices

- **GAP-020 (NEW): Unpatched Web Application on Portal** — MedDefense portal (web-srv-01) had access control bypass (Incident B, Exercise 1); no documented application security assessment or patch management
  - **Severity:** CRITICAL — Patient portal is internet-facing; unpatched vulnerabilities = direct access to internal network; Breach 3 started from identical attack vector
  - **Evidence:** Exercise 1 Incident B (Feb 2) shows broken access control; web framework unknown; patch cycle unknown; no SAST/DAST program

**Blind Spot Check:** ✓ **NEWLY IDENTIFIED GAPS** — Medical device security (GAP-017, GAP-018, GAP-019) was NOT comprehensively addressed in original gap analysis. Exercise 6 addressed MRI compensating controls but not enterprise medical IoT security program.

## Priority Reassessment

### **Gaps Upgraded from High to CRITICAL:**

| Gap ID | Title | Original Level | New Level | Justification |
|--------|-------|-----------------|-----------|---|
| GAP-002 | SIEM / Network Detection | High → | **CRITICAL** | All three breaches had extended dwell time (3 hrs, 47 days, 23 days) invisible to detection systems. MedDefense has ZERO network monitoring; identical exposure. |
| GAP-004 | MFA on Remote Access | High → | **CRITICAL** | Breach 2 exploited lack of MFA for 47 days; MedDefense has ZERO MFA except James Chen. Westside/HQ VPN + remote laptops (30 units) unprotected. |
| GAP-001 | Medical IoT Segmentation | Critical | Remains **CRITICAL** | Breach 3 directly exploited flat network to pivot from portal to infusion pumps. MedDefense flat network enables identical scenario; life-safety devices unprotected. |

### **Gaps Promoted from Not-Previously-Identified to CRITICAL:**

| Gap ID | Title | Risk Level | Justification |
|--------|-------|-----------|---|
| GAP-012 | Perimeter Device Patch Management | CRITICAL | Breach 1 started with unpatched VPN appliance CVE. MedDefense Westside router (Netgear VPN endpoint) patch status unknown; firmware unknown; critical vulnerability. |
| GAP-013 | MFA on All Remote/VPN Access | CRITICAL | Breach 2 exploited retained credentials (no MFA). MedDefense has zero enforcement; identical exposure across 30 laptops + Westside + HQ VPN. |
| GAP-014 | Automated Account Offboarding | CRITICAL | Breach 2 occurred because offboarding required manual manager ticket (manager forgot). MedDefense has manual process; any departing employee (2,000 staff) could retain access. |
| GAP-015 | Log Review & Behavioral Monitoring | CRITICAL | Breach 2 audit trail existed but was never reviewed ("logs without review = security theater"). MedDefense logs exist; no continuous review; no behavioral analytics. |
| GAP-016 | Data Loss Prevention (DLP) | CRITICAL | Breach 2 exported 3,211 records without alert. MedDefense has zero DLP; 50,000 patient records in EHR exportable without detection. |
| GAP-018 | Default Credentials on Medical Devices | CRITICAL | Breach 3 accessed infusion pump console with admin/admin. MedDefense ~200 medical devices; default credentials likely unchanged; no credential management program. |
| GAP-019 | Medical Device Firmware Vulnerability Management | CRITICAL | Breach 3 exploited device with known CVEs (security bulletin ignored). MedDefense BD Alaris v12.1.2 has known CVEs; no firmware update program. |

### **Gaps Downgraded (None, but some remain Medium/High):**

| Gap ID | Title | Current Level | Rationale |
|--------|-------|---|---|
| GAP-003 | Database Encryption at Rest | High | All three breaches involved lateral movement / access to systems, not database breaches specifically. Encryption protects against theft but doesn't prevent access. Remains important but not as urgent as detection/prevention gaps. Defer to Year 2. |
| GAP-009 | Session Timeout / Screen Lock | Medium | Breach 2 involved remote access; session timeout didn't matter. MedDefense screen lock policy weak (Exercise 3 Observation 3: idle EHR session 15+ min); important but secondary to MFA. |

## Pattern Analysis

**Common Factor Across All Three Breaches: DETECTION DELAY IS THE KILLER.** Breach 1 took 3 hours to reach AD domain controller with zero alerts; Breach 2 took 47 days before a patient noticed fraud; Breach 3 took 23 days before a technician noticed odd traffic. In each case, the organization's detection capability determined the damage: Breach 1's 11-day outage was recovery time; Breach 2's 3,211 records were exfiltrated over 6 weeks; Breach 3's 23-day dwell time allowed full reconnaissance of medical devices and default credentials. MedDefense is in the worst position: it has ZERO SIEM, ZERO continuous log review, ZERO behavioral monitoring, ZERO DLP, ZERO medical device monitoring. This means a ransomware attack identical to Breach 1 would not be detected until patient harm or operational failure occurs (EHR goes dark). An insider like Breach 2 would exfiltrate 50,000 records without a single alert. Medical device exploitation like Breach 3 would continue invisibly for weeks. **The second common factor: attackers exploit the path of least resistance.** Breach 1 found unpatched VPN. Breach 2 found retained credentials and no MFA. Breach 3 found default device credentials and flat network. **MedDefense should immediately prioritize three categories of investment over everything else:** (1) **Detection infrastructure (SIEM, EDR, behavioral monitoring, DLP)** — currently zero, enabling weeks of undetected compromise; (2) **Authentication hardening (MFA, automated offboarding, credential management)** — currently manual and permissive; (3) **Medical IoT security (segmentation, firmware management, default credential removal)** — currently unmanaged. The organization has adequate perimeter firewalls and backup software, but these are useless without the ability to detect when attackers have bypassed the perimeter, and they are catastrophic when backups are co-located with production. Budget allocation: shift from preventive/defensive controls to detection/response capabilities.
