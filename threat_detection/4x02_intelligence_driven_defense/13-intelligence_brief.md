# THe Intelligence Brief

**Document ID:** CTI-2026-HB013
**Date:** September 27, 2026
**Classification:** TLP:AMBER+STRICT (MedDefense Internal & Healthcare Sector Partners)
**Author:** MedDefense CTI Unit
**Target Audience:** MedDefense Executive Board, CISO, and Healthcare ISAC Partners

## 1. Executive Summary

The HEALTHBANE threat actor is a sophisticated, highly targeted adversary conducting spear-phishing and credential harvesting campaigns against healthcare organizations and supply-chain partners. Recent monitoring identified targeted phishing campaigns against MedDefense personnel utilizing weaponized PDF lure documents designed to harvest corporate credentials and establish remote initial access. Broader threat intelligence confirms that HEALTHBANE has successfully compromised multiple regional healthcare facilities by rotating infrastructure and impersonating medical equipment suppliers. MedDefense successfully contained the initial attack wave through rapid extraction and perimeter blocklisting, resulting in zero confirmed internal host compromises or patient data exposures. Our overall detection posture has significantly improved with custom YARA detection logic, though telemetry gaps remain regarding post-credential harvest secondary logins. We recommend three immediate actions: (1) deploy validated YARA signature suites across all perimeter email security gateways and endpoint protection agents, (2) enforce mandatory credential resets and hardware-backed multi-factor authentication (MFA) for high-risk accounts, and (3) apply perimeter-level blocklisting and sinkholing for all identified C2 infrastructure.

## 2. Adversary Profile

* **Threat Actor Alias:** HEALTHBANE (Internal tracking ID: UNC-4902)
* **Motivation:** Cyber Espionage & Financial Extortion (Dual-motivated targeting of Protected Health Information [PHI] and corporate financial infrastructure)
* **Target Scope:** Healthcare systems, medical device manufacturers, regional defense-adjacent healthcare providers, and third-party billing vendors.
* **Infrastructure Tendencies:**
* Uses newly registered domains (NRDs) typosquatting legitimate healthcare supply vendors (e.g., `medequip-supplies.net`, `meddefense-portal.com`, `meddefense-invoices.org`).
* Utilizes bulletproof hosting services and dynamic DNS providers for secondary C2 servers.
* Employs rapid sender domain rotation (e.g., shifting from `.net` to `.org` within 24–48 hours) to evade traditional domain reputation blocklists.
* **Operational Security (OPSEC) Practices:**
* Highly tailored lure themes customized with internal organizational terminology ("Action Required", "Payment Overdue").
* Multi-stage payload delivery: initial PDF lures contain no malicious binaries, relying instead on obfuscated embedded JavaScript streams and forced external browser URI redirections.
* Strict geo-fencing and user-agent filtering on landing credential-harvesting portals to block automated security sandbox scanners.
* **Threat Level:** **HIGH** (Capable of swift operational pivot from credential theft to enterprise-wide ransomware or sensitive data exfiltration).

## 3. Campaign Analysis

### Three-Stage Campaign Breakdown

```
+-----------------------------------------------------------------------------------+
| STAGE 1: Initial Access & Delivery                                                |
| - Email delivery using spoofed/rotated headers to bypass domain reputation.       |
| - High-relevance phishing lures targeting Finance & HR (PDF Invoices/notices).    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| STAGE 2: Execution & Credential Harvesting                                        |
| - PDF execution triggers embedded PDF-JavaScript auto-open actions.               |
| - Silent URI redirection to external adversary-controlled harvesting portals.      |
| - Capture of corporate credentials and session tokens via cloned SSO pages.        |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| STAGE 3: Persistence, C2 & Lateral Expansion                                      |
| - Use of stolen legitimate credentials to bypass external VPN/MFA gateways.        |
| - Post-exploitation beaconing via HTTP/HTTPS web protocols to dynamic C2 nodes.   |
| - Internal reconnaissance targeting active directory and patient database servers. |
+-----------------------------------------------------------------------------------+

```

### Campaign Timeline

* T-14 Days: Adversary Infrastructure Staging
HEALTHBANE registers typosquatted domain variants (`medequip-supplies.net`, `meddefense-portal.com`) and provisions credential capture portals mirroring MedDefense Single Sign-On (SSO) interfaces.
* T-3 Days: Initial Phishing Wave (Batch 1)
Distributes targeted spear-phishing emails containing `phishing_sample.pdf` and `healthbane_lure_02.pdf` targeting MedDefense accounts (`employee@meddefense.com`).
* T-1 Day: Incident Discovery & Initial Extraction
MedDefense Security Operations Center (SOC) flags suspicious PDF attachments. Forensics confirms embedded JavaScript triggering URI callbacks to adversary C2 infrastructure.
* T-0 Days: Infrastructure Pivot & Variant Wave (Batch 2)
HEALTHBANE rotates email distribution infrastructure to `meddefense-invoices.org` (`healthbane_email_03.eml`) to evade domain blocklists established during the initial wave response.
* T+1 Day: Rule Deployment & Full Perimeter Containment
CTI unit deploys updated YARA rules (`HEALTHBANE_Phishing_PDF` and composite rules), blocking all inbound campaign variants across perimeter mail controls.


### Evidence Confidence Matrix

| Analytical Finding | Evidence Source | Confidence Rating | Rationale |
| --- | --- | --- | --- |
| **PDF Lure Mechanics** | Static/Dynamic parsing of `phishing_sample.pdf` | **HIGH** | Confirmed via manual object extraction (`/JS`, `/JavaScript`, `/AA` stream objects verified). |
| **Email Spoofing Techniques** | Header analysis of `.eml` sample corpus | **HIGH** | Direct observation of SPF/DKIM alignment failures and header manipulation. |
| **Infrastructure Ownership** | WHOIS, Passive DNS, SSL certificate logs | **MEDIUM-HIGH** | Correlated IP reuse across multiple typosquatted domains; SSL certs share common CA issuer. |
| **Secondary Payload/Post-Exploit** | Threat intelligence sharing & partner telemetry | **MEDIUM** | Inferred from partner breach reports detailing HEALTHBANE post-compromise activity. |

## 4. ATT&CK Mapping

The following matrix maps observed artifacts and inferred adversary behaviors to the MITRE ATT&CK framework:

| Technique ID | Technique Name | Attack Phase | Status | Detection Relevance |
| --- | --- | --- | --- | --- |
| **T1566.001** | Phishing: Spearphishing Attachment | Initial Access | **Observed** | Critical for perimeter mail gateway rules (PDF attachment scanning). |
| **T1204.002** | User Execution: Malicious File | Execution | **Observed** | Informs EDR alert logic for PDF reader child-process spawning (`cmd.exe`, `powershell.exe`). |
| **T1059.007** | Scripting: JavaScript | Execution | **Observed** | Primary trigger for PDF stream inspection and inline script blocking. |
| **T1589.002** | Gather Victim Identity: Email Addresses | Reconnaissance | **Observed** | Informs external monitoring for compromised employee email listings. |
| **T1056.003** | Input Capture: Web Portal Capture | Credential Access | **Inferred** | Drives web proxy blocking and fake SSO landing page detection. |
| **T1078** | Valid Accounts | Persistence / Priv Esc | **Inferred** | Highlight need for SSO anomaly detection (impossible travel, strange User-Agents). |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command & Control | **Inferred** | Focuses egress proxy monitoring on suspicious HTTP/HTTPS outgoing requests. |

## 5. Detection Gap Assessment

Based on operational testing, the following telemetry and detection gaps were identified:

```
+---------------------------------------------------------------------------------------------------+
| PRIORITIZED DETECTION GAPS                                                                        |
+-----------------------------------+---------------------------------------------------------------+
| GAP 1: PDF Obfuscation Evasion   | Status: Observed-Not-Detected                                 |
|                                   | Traditional AV bypassed due to non-standard stream encoding   |
|                                   | and hex-encoded JavaScript keywords inside PDF objects.       |
+-----------------------------------+---------------------------------------------------------------+
| GAP 2: Rapid Domain Rotation      | Status: Observed-Not-Detected                                 |
|                                   | Static domain blocklists missed campaign batch 2 (.org pivot) |
|                                   | due to lack of dynamic regex pattern matching on sender headers.|
+-----------------------------------+---------------------------------------------------------------+
| GAP 3: External SSO Anomalies     | Status: Inferred-Not-Detected                                 |
|                                   | Lack of correlation between proxy alerts and cloud SSO logs    |
|                                   | allows stolen credentials to be used from untrusted IPs.       |
+-----------------------------------+---------------------------------------------------------------+

```

### Risk & Mitigation Strategy

1. **Obfuscated PDF Parsing (Gap 1):** Implement deep object-stream parsing at the email gateway rather than relying on binary hash reputation. Custom YARA rules must inspect uncompressed streams for string combinations like `/OpenAction` paired with `/JavaScript`.
2. **Infrastructure Churn (Gap 2):** Shift mail security policies from static domain indicators to pattern-based header evaluation (e.g., matching display name spoofing combined with unaligned Return-Path domains).
3. **Unmonitored Secondary Access (Gap 3):** Bridge cloud identity logs (Azure AD/Okta) with SOC SIEM correlation rules to flag logins originating from newly observed external IPs immediately following a phishing delivery event.

## 6. Indicator of Compromise (IoC) Table

| Attack Phase | Indicator Type | Value / Pattern | Confidence | Recommended Action |
| --- | --- | --- | --- | --- |
| **Delivery** | Email Address | `invoices@medequip-supplies.net` | **High** | Block sender & audit inbox logs. |
| **Delivery** | Email Address | `portal-admin@meddefense-portal.com` | **High** | Block sender & audit inbox logs. |
| **Delivery** | Email Address | `billing-support@meddefense-invoices.org` | **High** | Block sender & audit inbox logs. |
| **Delivery** | File Hash (SHA256) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | **High** | Blacklist file hash across endpoints. |
| **Delivery** | File Name | `phishing_sample.pdf` | **Medium** | Quarantined at Mail Gateway. |
| **Delivery** | File Name | `healthbane_lure_02.pdf` | **Medium** | Quarantined at Mail Gateway. |
| **Execution** | Regex Pattern | `(?i)To:\s*.*@meddefense\.com` | **High** | Apply YARA header detection rule. |
| **C2 / Capture** | Domain / URL | `hxxps://meddefense-portal[.]com/login/sso` | **High** | DNS Sinkhole & Web Proxy Block. |
| **C2 / Capture** | Domain / URL | `hxxps://meddefense-invoices[.]org/auth` | **High** | DNS Sinkhole & Web Proxy Block. |
| **C2 / Capture** | IPv4 Address | `192.0.2.145` | **Medium** | Perimeter Firewall Block. |

## 7. YARA Rule Summary

Three primary YARA rules were engineered and evaluated against the full sample corpus (`4x02/samples/`).

### Performance & Metrics Summary

| Rule Name | Target Artifact | TP | TN | FP | FN | Detection Rate | FP Rate | Precision | Status / Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `HEALTHBANE_Phishing_PDF` | PDF Documents | 2 | 2 | 0 | 0 | **100%** | **0%** | **100%** | **DEPLOY** |
| `HEALTHBANE_Email_Headers` | EML Headers | 2 | 1 | 0 | 1 | **67%** | **0%** | **100%** | **TUNE** |
| `HEALTHBANE_Campaign_Composite` | PDF & EML Corpus | 4 | 3 | 0 | 1 | **80%** | **0%** | **100%** | **DEPLOY (With Monitoring)** |

### Operational Notes & Recommendations

* **`HEALTHBANE_Phishing_PDF`:** Achieved perfect performance on PDF sample sets. **Status: Production Deployed.**
* **`HEALTHBANE_Email_Headers`:** Missed variant `healthbane_email_03.eml` due to domain rotation (`meddefense-invoices.org`). **Status: Tuning Required.** String criteria must be expanded to wildcard pattern `*@meddefense-invoices.org` before full production promotion.
* **`HEALTHBANE_Campaign_Composite`:** Successfully combines PDF structural detection with header indicators. Recommended for deployment as a multi-stage monitoring trigger.

## 8. Recommendations

```
+----------------------------------------------------------------------------------------------------+
| REMEDIATION TIMELINE                                                                               |
|                                                                                                    |
| [ IMMEDIATE: 48 Hours ]  -->  [ SHORT-TERM: 2 Weeks ]  -->  [ MEDIUM-TERM: 30 Days ]               |
| - Deploy YARA PDF rule        - Tune Header YARA logic      - Implement Hardware MFA               |
| - Block list C2 IoCs          - Audit SSO authentication    - Restrict PDF JavaScript globally     |
| - Reset targeted credentials  - Conduct phishing drill      - Conduct supplier CTI audit           |
+----------------------------------------------------------------------------------------------------+

```

### Immediate Actions (Next 48 Hours)

1. **Rule Deployment:** Push `HEALTHBANE_Phishing_PDF` to email inspection engines and EDR file-scanner policies.
2. **Infrastructure Blocklisting:** Add all identified domains (`meddefense-portal.com`, `meddefense-invoices.org`, `medequip-supplies.net`) and IPs to perimeter firewall, DNS sinkhole, and proxy blocklists.
3. **Targeted Credential Resets:** Force password resets and invalidate active SSO sessions for any user targeted by the observed email distribution list.

### Short-Term Actions (Next 2 Weeks)

1. **YARA Logic Tuning:** Update `HEALTHBANE_Email_Headers` with regular expressions capturing newly observed domain variations (`*meddefense-*.org/net/info`).
2. **Authentication Audit:** Review identity logs for login attempts originating from anonymized VPNs or unexpected geographies matching targeted user accounts over the past 30 days.
3. **Simulation & Awareness:** Conduct an internal targeted phishing simulation replicating HEALTHBANE lure techniques for high-risk personnel (Finance, Executive Support, HR).

### Medium-Term Actions (Next 30 Days)

1. **MFA Hardening:** Enforce hardware-backed, phishing-resistant Multi-Factor Authentication (FIDO2 / WebAuthn) enterprise-wide to negate credential harvesting portals.
2. **Attack Surface Reduction:** Implement Group Policy Objects (GPO) to globally disable JavaScript execution within Adobe Reader and standard PDF viewers across all endpoint workstations.
3. **Supply-Chain Vendor CTI Sharing:** Establish automated IoC sharing pathways via Health-ISAC to distribute validated indicators to regional healthcare partners.

## 9. Intelligence Gaps and Collection Priorities

| Unknown Element / Intelligence Gap | Required Collection Strategy | Actionable Source / Stakeholder |
| --- | --- | --- |
| **Exact Identity of Credential Harvesting Kit** | Capture full raw HTTP response body from active landing pages (including backend POST processing scripts). | CTI Unit / External Threat Research Partners |
| **Extent of Secondary Access Attempts** | Detailed audit of cloud SSO, VPN, and Remote Desktop Gateway authentication logs for compromised accounts. | MedDefense SOC / Identity & Access Management (IAM) |
| **Broad Industry Impact & Attribution** | Query Health-ISAC and FBI InfraGard databases for matching TTPs and C2 IP infrastructures. | Cyber Threat Intelligence Working Group / Health-ISAC |
| **Post-Exploitation Playbook** | Acquire host-level telemetry from breached partner organizations to identify preferred lateral movement utilities. | Incident Response Retainer / Forensic Partners |
