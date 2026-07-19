# 13. The Web Exposure

### Host Analysis

| Host | Exposure | Web-related Findings |
| --- | --- | --- |
| **web-srv-01** (10.10.2.10) | **Internet-facing** | 017 (Tomcat Info Disclosure), 031 (Ghostcat/AJP), 012 (Missing Headers), 021 (HTTP TRACE) |
| **NAS-01** (10.10.2.41) | **Internal-only** | 015 (NAS Web Interface Public/Accessible) |
| **Grafana-srv** (10.10.2.50) | **Internal (Flat)** | 029 (Vulnerable Grafana version) |

### Risk Assessment

#### 1. web-srv-01 (Patient Portal)

* **Combined Risk:** **Critical.** This host sits on the edge of our network. It suffers from a "chained vulnerability" profile: Finding 017 (Info Disclosure) provides the version fingerprinting necessary to confirm the existence of Finding 031 (Ghostcat), a remote code execution (RCE) flaw.
* **Attack Scenario:** An attacker performs a standard reconnaissance scan of the public IP, identifying the Apache Tomcat version via Finding 017. They confirm the target is vulnerable to Ghostcat (031), then leverage the AJP connector to read arbitrary files or execute code, gaining a foothold in the DMZ.
* **Priority:** **1 (Highest).** Internet-facing assets with RCE vulnerabilities are the primary target for automated ransomware bots.

#### 2. NAS-01 (Synology)

* **Combined Risk:** **Medium/High.** The management interface is exposed, but only internally. The risk is primarily lateral movement rather than external exploitation.
* **Attack Scenario:** An attacker, having already gained a foothold on the internal network, accesses the NAS web interface (015). They attempt default credential brute-forcing, as many NAS devices are deployed without changing factory settings, potentially leading to the loss of all backup data.
* **Priority:** **3.** Critical for data integrity, but less likely to be the "initial entry point" for an external adversary compared to the patient portal.

#### 3. Grafana-srv

* **Combined Risk:** **High.** While not public-facing, this host is on the "flat network," meaning any compromised internal workstation can reach it. Grafana is a high-value target for attackers looking to exfiltrate operational telemetry or pivot into backend systems.
* **Attack Scenario:** An attacker gains access to a user workstation via phishing. Once inside, they scan the internal subnet and discover the vulnerable Grafana instance (029). They exploit the version-specific flaw to bypass authentication and access system dashboards containing backend database credentials.
* **Priority:** **2.** Urgent, but secondary to the internet-facing portal.

### Finding 017 (Tomcat information disclosure) led SecurePoint to manually discover Finding 031 (Ghostcat - CVSS 9.8). What does this tell you about the value of investigating "Medium" findings that reveal version information ?

The discovery of Finding 031 (Ghostcat) via the "Medium" Finding 017 (Tomcat information disclosure) proves that **vulnerability management is a chain, not a list of isolated issues.**

"Medium" information disclosure findings are often dismissed as "noise" by automated scanners, but they serve as the **reconnaissance phase** for an attacker. By leaking the server version, Finding 017 provided the exact "map" an attacker needed to locate the "treasure" (the RCE vulnerability in Finding 031). This confirms that a vulnerability manager must treat low-severity fingerprinting findings as high-priority intelligence; they are not bugs to be patched, but **tactical intelligence leaks** that inform an attacker’s exploit selection. Investigating these "Medium" findings essentially denies the attacker the ability to customize their payload, forcing them to "blindly" guess, which significantly increases the chance of detection by our IDS/IPS.
