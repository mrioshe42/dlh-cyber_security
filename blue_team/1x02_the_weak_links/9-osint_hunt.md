# 9. The OSINT Hunt

### OSINT Vulnerability Assessment

| Asset | Vulnerability / Threat | Severity |
| --- | --- | --- |
| **FortiGate 100F** | CVE-2026-24858 (SSO Bypass) | Critical (9.4) |
| **O365 / Entra ID** | OAuth Consent Abuse & AiTM Attacks | High (Methodological) |
| **Synology DSM 7** | CVE-2026-13136 (Arbitrary File Access) | Critical (10.0) |

### Detailed Analysis

#### 1. FortiGate 100F (FortiOS)

* **Source:** [SOC Prime (CVE-2026-24858 Analysis)](https://socprime.com/blog/cve-2026-24858-vulnerability/)
* **CVE:** CVE-2026-24858
* **Affected Product:** FortiGate 100F (FortiOS)
* **Why the Scan Missed It:** The vulnerability is an authentication bypass in FortiCloud SSO, which is often an "off-scanner" configuration setting. Automated scanners often focus on unauthenticated network service ports, missing authenticated management interface bypasses.
* **CVSS / Severity:** 9.4 / Critical
* **MedDefense Impact:** An attacker could bypass SSO authentication to create new local admin accounts, gaining full control of the firewall and the ability to pivot into the medical network.
* **Recommendation:** Immediately update FortiOS to the latest patch level. Verify if the "Allow administrative login using FortiCloud SSO" toggle is active; if not strictly required, disable it.

#### 2. Microsoft O365 / Entra ID

* **Source:** [Microsoft Security Blog (Defending SaaS-based applications)](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
* **CVE:** N/A (Logical/Configuration Vulnerability)
* **Affected Product:** Microsoft 365 E3 Environment
* **Why the Scan Missed It:** Cloud-native environments (SaaS) lack a traditional "host" to scan. Scanners cannot inspect the tenant configuration, OAuth app permissions, or user session state.
* **CVSS / Severity:** High (Methodological Risk)
* **MedDefense Impact:** Adversaries can use "consent phishing" (vishing or malicious OAuth apps) to hijack user sessions. This allows data exfiltration from email and OneDrive without ever needing the user's password.
* **Recommendation:** Implement Conditional Access policies to restrict OAuth app consent permissions. Transition to phishing-resistant authentication methods (Passkeys/FIDO2) as mandated by Microsoft's 2026 security roadmap.

#### 3. Synology DSM 7

* **Source:** [Synology Security Advisory (Synology_SA_26_11)](https://www.synology.com/en-global/security/advisory/Synology_SA_26_11)
* **CVE:** CVE-2026-13136
* **Affected Product:** Synology DSM 7
* **Why the Scan Missed It:** The vulnerability is inside the MailPlus Server package. If the scan was configured for general "OS-level" port discovery, it likely skipped application-specific package vulnerabilities.
* **CVSS / Severity:** 10.0 / Critical
* **MedDefense Impact:** Allows remote attackers to read/write arbitrary files, potentially leading to full system compromise or a denial-of-service attack on backup services.
* **Recommendation:** Upgrade the MailPlus Server package immediately to version 4.0.1-31663 or higher. Restrict management interface access to internal-only subnets to mitigate remote exploit attempts.