# 9. The OSINT Hunt: Vulnerability & Threat Assessment

### Executive Summary

Automated vulnerability scanning provides a necessary baseline for patch management but is insufficient for a modern threat landscape. Scanners are inherently limited to IP-addressable hosts and known plugin databases, creating critical visibility gaps in **SaaS-based identity flows**, **authentication bypass logic**, and **active threat campaigns**. This report details high-risk exposures identified through manual OSINT research that were absent from the automated vulnerability scan report.

### Summary of Findings

| Asset | Vulnerability / Threat | Severity |
| --- | --- | --- |
| **FortiGate 100F** | CVE-2026-24858 (SSO Authentication Bypass) | Critical (9.4) |
| **O365 / Entra ID** | Kali365 OAuth Device Code Phishing | High |
| **Synology DSM 7** | CVE-2026-40530 (CRLF Injection) | High (8.0) |

### Detailed Analysis

#### 1. FortiGate 100F (FortiOS)

* **Source:** [SOC Prime: CVE-2026-24858 Analysis](https://socprime.com/blog/cve-2026-24858-vulnerability/) | [Canadian Centre for Cyber Security Advisory AV26-023](https://www.cyber.gc.ca/en/alerts-advisories/fortinet-security-advisory-av26-023)
* **CVE:** `CVE-2026-24858`
* **Affected Product:** FortiOS (FortiCloud SSO)
* **Why the Scan Missed It:** Scanners operate on the perimeter, checking for open ports and services. This vulnerability exists in the **FortiCloud SSO logic**—a cloud-based authentication path. Because the flaw is in the authentication *integration* rather than a binary service running on the box itself, traditional scanners cannot trigger the SSO bypass mechanism.
* **MedDefense Impact:** This allows attackers to bypass authentication and gain local admin access to the firewall. As the primary gateway for a 350-bed hospital, unauthorized access to the FortiGate would enable an adversary to disable network segmentation, intercept medical imaging data, and facilitate lateral movement throughout the clinical network.
* **Recommendation:** Apply the firmware patch immediately. Disable the "Allow administrative login using FortiCloud SSO" toggle in the registration settings until patched.

#### 2. Microsoft O365 / Entra ID (Identity Layer)

* **Source:** [FBI IC3 Alert I-052126-PSA: Kali365 Phishing Campaign](https://www.ic3.gov/PSA/2026/PSA260521)
* **CVE:** N/A (Methodological Threat)
* **Affected Product:** Microsoft 365 E3 Environment
* **Why the Scan Missed It:** Scanners are blind to the "Identity Layer." They cannot simulate a user receiving a social engineering lure or interacting with a browser-based OAuth consent flow. The scan measures infrastructure state, not user behavior or configuration trust boundaries.
* **MedDefense Impact:** Kali365 is a Phishing-as-a-Service (PhaaS) platform that captures OAuth tokens. By tricking a staff member into "authorizing" an app, an attacker gains persistent access to Outlook/OneDrive. This bypasses MFA and password resets, potentially leading to the breach of patient emails containing sensitive PHI, circumventing traditional boundary security.
* **Recommendation:** Create a Conditional Access Policy to **block device code flow** for all users, except for specific, IT-approved service accounts. Conduct an audit of existing OAuth grants.

#### 3. Synology DSM 7 (Network Attached Storage)

* **Source:** [National CSIRT Cyprus: Multiple Vulnerabilities in Synology DSM (2026)](https://www.google.com/search?q=https://csirt.cy/en/cve/2026/multiple-vulnerabilities-in-synology-dsm/)
* **CVE:** `CVE-2026-40530`
* **Affected Product:** Synology DiskStation Manager (DSM) 7.x
* **Why the Scan Missed It:** This vulnerability involves improper authorization checks in V1 APIs. Standard network scanners often lack the specialized plugin library required to fuzz proprietary NAS API endpoints. They report the service as "Active" but lack the context-specific knowledge to test the logic of the API authentication flow.
* **MedDefense Impact:** CRLF Injection (CVSS 8.0) allows for arbitrary file reading. Since this NAS houses archived patient documentation and clinical backups, an attacker could exfiltrate years of medical history or disrupt clinical operations by corrupting backup data, directly impacting HIPAA compliance and patient care continuity.
* **Recommendation:** Update DSM immediately to `7.3.2-86009-2` or higher. Ensure the NAS management interface is isolated from the WAN and restricted via VPN.

### Methodology: Threat Intelligence Integration

To bridge the gap between automated scanning and the current threat landscape, this OSINT hunt employed a three-tier validation process:

1. **Advisory Verification:** Cross-referenced findings against official national cybersecurity centers (e.g., CISA, CCCS, CSIRT Cyprus) to confirm the existence and impact of the disclosed vulnerabilities.
2. **Vector Analysis:** Assessed the "Blind Spots" of current scanners, specifically identifying where agentless infrastructure (SaaS) and proprietary APIs (NAS/Firewall) fall outside the scope of traditional port-based scanning.
3. **Business Context Mapping:** Evaluated the findings not based on raw CVSS scores alone, but on the *clinical impact* (e.g., PHI exposure, backup corruption, boundary compromise) to align with MedDefense’s operational risk profile.
