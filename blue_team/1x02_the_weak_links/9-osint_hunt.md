# 9. The OSINT Hunt

### OSINT Vulnerability Assessment

| Asset | Vulnerability / Threat | Severity |
| --- | --- | --- |
| **FortiGate 100F** | CVE-2026-21643 (SQL Injection) | Critical (9.8) |
| **O365 / Entra ID** | OAuth Consent Phishing (ShinyHunters TTPs) | High (Methodological) |
| **Synology DSM 7** | CVE-2026-13136 (Arbitrary File Access) | High (7.5) |

### Detailed Analysis

#### 1. FortiGate 100F (FortiOS)
*   **Source:** [Canadian Centre for Cyber Security (Fortinet Security Advisory AV26-096)](https://www.cyber.gc.ca/en/alerts-advisories/fortinet-security-advisory-av26-096)
*   **CVE:** CVE-2026-21643
*   **Affected Product:** FortiOS (Administrative Interface)
*   **Why the Scan Missed It:** Automated vulnerability scanners are often configured for "light" discovery of unauthenticated ports. This SQL injection vulnerability exists within the administrative interface and requires specific, authenticated or non-standard HTTP request handling that typical network vulnerability scanners often fail to traverse or fingerprint accurately.
*   **CVSS / Severity:** 9.8 / Critical
*   **MedDefense Impact:** An unauthenticated attacker could perform SQL injection to bypass authentication, potentially leading to administrative console takeover and full compromise of the firewall, effectively providing a foothold to pivot into the clinical network.
*   **Recommendation:** Apply the firmware update immediately as specified in the vendor advisory. Restrict management interface access to a dedicated, internal-only management VLAN, disabling public-facing admin interfaces entirely.

#### 2. Microsoft O365 / Entra ID
*   **Source:** [Microsoft Security Blog (Defending SaaS-based applications against ShinyHunters OAuth abuse)](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
*   **CVE:** N/A (Methodological Threat / OAuth Abuse)
*   **Affected Product:** Microsoft 365 E3 Environment
*   **Why the Scan Missed It:** Cloud-native SaaS platforms do not have a "host" footprint that traditional vulnerability scanners can probe. The risk is logical—based on user trust and configuration—not a software bug in a listening service that a network scanner can detect.
*   **CVSS / Severity:** High (Methodological Risk)
*   **MedDefense Impact:** Adversaries utilizing vishing or consent phishing can trick employees into authorizing a malicious OAuth application. This allows attackers to hijack sessions, exfiltrate patient email data, and maintain persistence without needing to bypass MFA or steal user passwords.
*   **Recommendation:** Implement Conditional Access policies to restrict OAuth app consent permissions. Specifically, restrict users from consenting to applications that require "High" risk permissions (e.g., Mail.Read, Files.ReadWrite) without admin review. Transition to phishing-resistant authentication methods (Passkeys/FIDO2).

#### 3. Synology DSM 7
*   **Source:** [Synology Security Advisory (Synology-SA-26:11)](https://www.synology.com/en-global/security/advisory/Synology_SA_26_11)
*   **CVE:** CVE-2026-13136
*   **Affected Product:** Synology MailPlus Server
*   **Why the Scan Missed It:** The vulnerability is specific to the "MailPlus Server" application package. A general network scan typically performs service discovery (ports 22, 80, 443) and OS fingerprinting, but rarely probes the deep internal logic of specific, installed third-party NAS packages unless the scanner has explicit, updated plugins for those specific applications.
*   **CVSS / Severity:** 7.5 / High
*   **MedDefense Impact:** Allows remote attackers to read or write arbitrary files, potentially leading to the leakage of archived medical documentation stored on the NAS or a Denial of Service (DoS) preventing the recovery of essential backups.
*   **Recommendation:** Upgrade the MailPlus Server package to the version specified in the advisory (or newer). Additionally, ensure the DSM management interface is not exposed to the public internet and use the built-in firewall rules to limit MailPlus access to authorized internal subnets only.
