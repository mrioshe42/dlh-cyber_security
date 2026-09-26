# 7-attack_navigator.md: MITRE ATT&CK Mapping for HEALTHBANE

## 1. Mapping Methodology

To bridge adversary behavior with actionable detection engineering, the HEALTHBANE campaign has been mapped to the MITRE ATT&CK Framework using a strict **two-tier methodology**:

* **OBSERVED (Score: 100 / Red):** Confirmed by direct internal telemetry (`meddefense_4x00_findings.txt`), authoritative government advisories (`HC3`), or high-fidelity reverse-engineering artifacts (`researcher_blog_analysis.txt`).
* **INFERRED (Score: 50 / Amber):** Logically deduced precursor or successor behaviors aligned with the campaign kill chain, though lacking direct point-of-origin telemetry in the current environment.

## 2. ATT&CK Techniques Organized by Tactic

### Tactic: Initial Access

* **T1566.001 - Phishing: Spearphishing Link**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Gateway logs confirmed phishing emails containing malicious URLs sent to healthcare workers.
* **Source:** MedDefense Internal Findings (`meddefense_4x00_findings.txt`) & HC3 Advisory
* **Attack Phase:** Stage 1 (Credential Harvesting)
* **T1566.002 - Phishing: Spearphishing Attachment**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Malicious Office attachments containing macro loaders identified in email samples.
* **Source:** Researcher Blog (`researcher_blog_analysis.txt`)
* **Attack Phase:** Stage 1 / Stage 2

### Tactic: Execution

* **T1204.002 - User Execution: Malicious File**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Users executed weaponized payloads or opened malicious links delivered via phishing.
* **Source:** Researcher Blog & Internal Endpoint Logs
* **Attack Phase:** Stage 2 (Malware Delivery)
* **T1059.001 - Command and Scripting Interpreter: PowerShell**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Obfuscated PowerShell execution commands found embedded in initial script drop artifacts.
* **Source:** Researcher Blog (`researcher_blog_analysis.txt`)
* **Attack Phase:** Stage 2

### Tactic: Persistence

* **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**
* **Classification:** INFERRED
* **Evidence/Reasoning:** Standard post-compromise persistence mechanism expected following secondary payload execution.
* **Source:** Threat Analysis Deduction
* **Attack Phase:** Stage 2 / Persistence

### Tactic: Privilege Escalation & Defense Evasion

* **T1078 - Valid Accounts**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Attackers actively utilized freshly harvested user credentials to access enterprise portals and move laterally.
* **Source:** MedDefense Internal Findings
* **Attack Phase:** Stage 2 / Access

### Tactic: Command and Control (C2)

* **T1071.001 - Application Layer Protocol: Web Protocols**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** Outbound HTTPS connections to external command infrastructure (`healthbane-c2.net`).
* **Source:** Commercial Feed & Firewall Logs
* **Attack Phase:** Stage 3 (Exfiltration)

### Tactic: Exfiltration

* **T1048 - Exfiltration Over Alternative Protocol (DNS Tunneling)**
* **Classification:** OBSERVED
* **Evidence/Reasoning:** High-volume anomalous DNS query patterns observed in egress packet captures, indicative of tunneling.
* **Source:** MedDefense Internal Findings (`meddefense_4x00_findings.txt`)
* **Attack Phase:** Stage 3 (Data Exfiltration)

## 3. Campaign Mapping Summary

1. **Total Techniques Identified:** 8 unique MITRE ATT&CK techniques.
2. **Observed vs. Inferred Ratio:** 6 Observed (75%) to 2 Inferred (25%), reflecting high fidelity across the data sources.
3. **Tactics with Most Coverage:** Initial Access (Phishing) and Execution/C2, anchored heavily by multi-source intake agreement.
4. **Tactics with Least Coverage:** Lateral Movement and Impact, representing blind spots in current telemetry or pre-disruption campaign phases.
5. **Techniques Most Important for Detection Planning:**
* **T1566.001 (Spearphishing Link):** Critical for perimeter email gateway defenses.
* **T1048 (DNS Exfiltration):** Essential for internal network monitoring and egress filtering.
* **T1059.001 (PowerShell Execution):** Paramount for endpoint detection rules (Sigma/YARA).
