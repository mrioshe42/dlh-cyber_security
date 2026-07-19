# 11. The False Positives

### Analysis of False Positives

| Finding ID | Reported Vulnerability | Why It Is a False Positive |
| --- | --- | --- |
| **022** | System clock skew detected | The scanner flagged a time variance against its own source. SecurePoint’s note confirms: "NTP delay, non-security impact." The target system is correctly syncing with the internal AD domain controller; the latency is network-induced, not a security flaw. |
| **018** | Kerberos supports weak encryption types | The scanner detected the *presence* of RC4 support in AD. However, our GPO policies explicitly *enforce* AES-256 for all tickets. The capability exists for legacy compatibility but is not the active protocol, rendering the "vulnerability" moot. |

#### 1. Finding 022: System Clock Skew

* **Validation Method:** Run `w32tm /query /status` (on Windows) or `ntpq -p` (on Linux) to verify synchronization against the primary domain source. Cross-reference the system log for NTP synchronization errors.
* **Risk of Acting on This FP:** Wasting engineering hours reconfiguring NTP servers or triggering unnecessary reboots on production servers for a non-existent security issue.
* **Risk of Not Validating:** If dismissed without check, you might miss a legitimate failure of the NTP service, which *can* cause authentication issues (Kerberos relies on time-stamped tickets). However, it is an operational outage risk, not an exploit risk.

#### 2. Finding 018: Kerberos Weak Encryption

* **Validation Method:** Use PowerShell (Active Directory module) to query `msDS-SupportedEncryptionTypes` for the domain and computer objects, and inspect the relevant GPO ("Default Domain Controllers Policy") to confirm the encryption enforcement settings.
* **Risk of Acting on This FP:** Disabling RC4 support globally could break legacy medical devices or older imaging equipment that rely on legacy encryption for domain authentication, potentially causing a localized denial-of-service in clinical operations.
* **Risk of Not Validating:** If you assume it is an FP but it is actually enabled, you remain vulnerable to "Kerberoasting" or downgrade attacks, where an adversary forces the service to negotiate weak RC4 encryption to crack tickets offline.

### In a scan report of 31 findings, what is a reasonable expected false positive rate for an automated scanner ? Why is manual validation essential before committing remediation resources ?

In a comprehensive vulnerability scan of 31 findings, a **False Positive (FP) rate of 10% to 20% is standard.** If your FP rate is significantly higher, your scanning tool is likely misconfigured or "noisy"; if it is near zero, your scanner may be too timid and missing true vulnerabilities.

Manual validation is essential before committing remediation resources because **context is the variable scanners cannot compute.** An automated tool can see a port, a service, and a version number, but it cannot know that:

1. **Compensating controls exist:** (e.g., a "vulnerable" service is actually behind a strict WAF or network ACL).
2. **Operational requirements override security defaults:** (e.g., legacy systems that *must* run specific protocols to function).
3. **The vulnerability is theoretical:** (e.g., the code is present but the vulnerable function is unreachable or disabled).

By validating, you stop "patching for the sake of patching" and instead focus your finite engineering budget on findings that genuinely improve the security posture of MedDefense.