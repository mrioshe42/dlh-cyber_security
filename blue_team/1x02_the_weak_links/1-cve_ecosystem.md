# 1. The CVE Ecosystem

### Critical: CVE-2021-44790
- **CVE ID:** CVE-2021-44790
- **NVD URL:** https://nvd.nist.gov/vuln/detail/CVE-2021-44790
- **Description:** A memory corruption flaw in Apache HTTP Server's mod_lua component allows an attacker to send a specially crafted request body that overflows a buffer, potentially leading to remote code execution.
- **Affected Products:** Apache HTTP Server 2.4.51, 2.4.50, 2.4.49 (and earlier versions).
- **CVSS v3.1 Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **CVSS Base Score:** 9.8
- **CWE:** CWE-120 (Buffer Copy without Checking Size of Input)
- **References:**
    1. https://httpd.apache.org/security/vulnerabilities_24.html (Vendor Advisory)
    2. https://lists.apache.org/thread/88358485 (Patch/Mailing List)
    3. https://security.netapp.com/advisory/ntap-20220114-0005/ (Third-party Advisory)
- **Published Date:** 2021-12-20
- **Last Modified:** 2023-01-20

### High: CVE-2021-34527
- **CVE ID:** CVE-2021-34527 (PrintNightmare)
- **NVD URL:** https://nvd.nist.gov/vuln/detail/CVE-2021-34527
- **Description:** A vulnerability in the Windows Print Spooler service allows authenticated users to perform remote code execution or escalate privileges by abusing the RpcAddPrinterDriverEx() function.
- **Affected Products:** Windows Server 2019, Windows 10 Version 20H2, Windows Server 2016.
- **CVSS v3.1 Vector String:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **CVSS Base Score:** 8.8
- **CWE:** CWE-269 (Improper Privilege Management)
- **References:**
    1. https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527 (Vendor Advisory)
    2. https://github.com/cube0x0/CVE-2021-34527 (PoC)
    3. https://kb.cert.org/vuls/id/383432 (Write-up/Alert)
- **Published Date:** 2021-07-06
- **Last Modified:** 2021-08-05

### Medium: CVE-2021-43798
- **CVE ID:** CVE-2021-43798
- **NVD URL:** https://nvd.nist.gov/vuln/detail/CVE-2021-43798
- **Description:** A path traversal vulnerability in Grafana allows unauthenticated remote attackers to read arbitrary files from the server's filesystem via specially crafted HTTP requests.
- **Affected Products:** Grafana 8.0.0, 8.1.0, 8.2.0.
- **CVSS v3.1 Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **CVSS Base Score:** 7.5
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **References:**
    1. https://grafana.com/blog/2021/12/07/grafana-vulnerability-advisory/ (Vendor Advisory)
    2. https://github.com/jas502n/Grafana-CVE-2021-43798 (PoC)
    3. https://security.gentoo.org/glsa/202208-25 (Third-party Advisory)
- **Published Date:** 2021-12-07
- **Last Modified:** 2022-09-02

---

## 2. CVE Ecosystem Questions

**Structure of a CVE ID:**
Consists of `CVE-YYYY-NNNNN`. `YYYY` is the year the CVE was assigned or publicly disclosed, and `NNNNN` is a sequential unique identifier.

**What is a CNA?**
A CVE Numbering Authority (CNA) is an organization authorized to assign CVE IDs to vulnerabilities affecting products within their specific scope (e.g., vendors, security firms, research groups).

**Lifecycle States:**
- **Reserved:** The ID has been allocated to a researcher/vendor but details are not yet public.
- **Published:** The vulnerability is public and technical details are available.
- **Rejected:** The ID was retired (e.g., duplicate, mistake, or invalid entry).

**Rejected Example:**
- **CVE:** CVE-2019-1010001
- **Reason:** Rejected by the CNA because it was determined to be a duplicate of another CVE ID already assigned to the same vulnerability.
