# The Detection Gap Analysis

## 1. Overview and Methodology

To transition from threat intelligence and mapping to active defense, this detection gap analysis compares the **HEALTHBANE MITRE ATT&CK mapping (`7-attack_navigator.md`)** against MedDefense's current internal detection posture (`meddefense_4x00_findings.txt`, egress monitoring controls, and indicator triage baselines).

Each technique is evaluated against existing defensive telemetry to assign one of three operational states:

* **DETECTED:** Covered by existing, automated YARA rules, indicator blocklists, or high-fidelity analytic alerts.
* **PARTIALLY DETECTED:** Telemetry exists or rules are configured, but coverage is narrow, relies on manual review, or prone to evasion.
* **NOT DETECTED:** Zero documented visibility or active detection engineering rules covering the technique.

## 2. Comprehensive Technique Gap Assessment

### 1. T1566.001 - Phishing: Spearphishing Link

* **Status / Classification:** OBSERVED | **Detection Status:** PARTIALLY DETECTED
* **Evidence:** Email gateway logs capture incoming headers and domains (`meddefense_4x00_findings.txt`), but dynamic newly-registered domains (DGA) frequently bypass static blocklists.
* **Gap Explanation:** Commercial feed indicators contain high false-positive noise and unvetted shared infrastructure, preventing automated blocking without risking legitimate mail delivery.
* **Recommendation:** Implement strict SPF/DKIM/DMARC enforcement, URL rewriting/sandbox inspection at the email gateway, and feed-derived domain blocklists vetted through local triage.

### 2. T1566.002 - Phishing: Spearphishing Attachment

* **Status / Classification:** OBSERVED | **Detection Status:** DETECTED
* **Evidence:** Local YARA rules and endpoint email attachment scanners identify macro-enabled Office documents and ISO loaders (`researcher_blog_analysis.txt`).
* **Gap Explanation:** Effective prevention, though novel packers or password-protected archives can occasionally evade static signature matching.
* **Recommendation:** Maintain robust YARA signature updates and enforce Group Policy restricting macro execution for non-admin users.

### 3. T1204.002 - User Execution: Malicious File

* **Status / Classification:** OBSERVED | **Detection Status:** PARTIALLY DETECTED
* **Evidence:** Host endpoint logs capture process execution, but standard user execution of scripts orlnk shortcuts generates low-confidence alerts requiring manual triage.
* **Gap Explanation:** Difficult to block outright without disrupting normal business workflows where clinical staff regularly open documents.
* **Recommendation:** Deploy Application Control (AppLocker / WDAC) to restrict script execution paths and unauthorized binary execution.

### 4. T1059.001 - Command and Scripting Interpreter: PowerShell

* **Status / Classification:** OBSERVED | **Detection Status:** DETECTED
* **Evidence:** Endpoint telemetry captures obfuscated PowerShell command-line arguments and script block logging (Event ID 4104).
* **Gap Explanation:** Highly visible if logging is enabled, though sophisticated adversaries may attempt AMSI bypasses.
* **Recommendation:** Ensure PowerShell Transcription and Script Block Logging remain globally enabled across all enterprise workstations.

### 5. T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

* **Status / Classification:** INFERRED | **Detection Status:** NOT DETECTED
* **Evidence:** No current baseline monitoring specifically alerts on unauthorized modifications to common persistence registry keys.
* **Gap Explanation:** Blind spot in endpoint configuration monitoring for persistence mechanisms following Stage 2 compromise.
* **Recommendation:** Implement Sysmon (Event ID 13) or EDR registry monitoring rules targeting `\Software\Microsoft\Windows\CurrentVersion\Run`.

### 6. T1078 - Valid Accounts

* **Status / Classification:** OBSERVED | **Detection Status:** PARTIALLY DETECTED
* **Evidence:** Identity provider (IdP) logs track successful logins, but distinguishing legitimate user behavior from stolen credential replay remains challenging.
* **Gap Explanation:** Attackers using valid user credentials from unflagged or residential proxy IPs blend seamlessly with legitimate remote access.
* **Recommendation:** Enforce phishing-resistant Multi-Factor Authentication (MFA) and implement behavioral user/entity behavior analytics (UEBA).

### 7. T1071.001 - Application Layer Protocol: Web Protocols (C2)

* **Status / Classification:** OBSERVED | **Detection Status:** PARTIALLY DETECTED
* **Evidence:** Firewall and proxy logs record outbound HTTPS traffic, but encrypted TLS payloads prevent inspection of command-and-control contents.
* **Gap Explanation:** High volumes of legitimate web traffic obscure anomalous C2 beacons communicating over standard ports (443).
* **Recommendation:** Implement TLS inspection at the perimeter proxy and threat intelligence feed indicator sinkhole matching for known C2 domains (`healthbane-c2.net`).

### 8. T1048 - Exfiltration Over Alternative Protocol (DNS Tunneling)

* **Status / Classification:** OBSERVED | **Detection Status:** NOT DETECTED
* **Evidence:** Standard DNS query logs are retained briefly, but no real-time frequency or entropy-based analytics monitor for DNS tunneling signatures.
* **Gap Explanation:** Egress DNS traffic is rarely inspected for encoded or abnormally long subdomain query volumes used in data theft.
* **Recommendation:** Deploy network packet analysis rules or DNS security monitoring looking for high query entropy and anomalous query length.

## 3. Prioritized Gap List & Remediation Plan

### Priority 1 Gaps (OBSERVED & NOT DETECTED)

* *None currently in this tier, as all observed exfiltration and C2 channels possess partial logging baselines.* (Immediate focus shifts to shoring up Priority 2 and Partials).

### Priority 2 Gaps (INFERRED & NOT DETECTED)

* **Technique:** `T1547.001` (Registry Run Keys)
* **Why the Gap Matters:** Leaves the enterprise blind to persistence mechanisms established during Stage 2 malware delivery.
* **Detection Idea:** Alert on unexpected write events to `CurrentVersion\Run` or `RunOnce` registry hives from non-installer parent processes.
* **Required Data Source:** Sysmon Event ID 13 (Registry Value Set) or Windows Security Event Logs.
* **Implementation Path:** Endpoint Security / System Administration Team.

### Priority 3 Gaps (PARTIALLY DETECTED)

* **Technique:** `T1048` / DNS Tunneling (Exfiltration) & `T1566.001` (Phishing Links)
* **Why the Gap Matters:** DNS tunneling is the primary vehicle for Stage 3 data theft, while phishing links drive initial entry.
* **Detection Idea:** Monitor for high DNS query volume per host with high Shannon entropy strings; build automated feedback loops from triaged commercial IOCs.
* **Required Data Source:** Internal DNS query logs, Firewall egress logs, Email Gateway telemetry.
* **Implementation Path:** Network Security Engineering & Security Operations Center (SOC).
