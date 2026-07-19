# 20. The Priority Matrix

### The Remediation Priority Matrix

| Horizon | ID | Description | Action | Owner | Est. Cost |
| --- | --- | --- | --- | --- | --- |
| **Immediate** | 031 | Ghostcat (RCE) | Patch Tomcat | IT | $1K |
| (24-48h) | 003 | SQLi (Billing) | Sanitize Inputs | Dev | $5K |
|  | 007 | LDAP Relay | Enable Signing/Binding | Security | $2K |
|  | 010 | Alaris Pump | Micro-segment (VLAN) | ClinEng | $5K |
|  | 016 | Philips Mon | Firewall rules | IT | $2K |
|  | 024 | IoT Gateway | Enforce MFA/Disable unauth | IT | $1K |
|  | 027 | Billing Agent | Reinstall EDR | Security | $1K |
|  | 029 | Grafana | Patch Version | IT | $1K |
|  | 006 | Billing App | Patch vulnerability | Dev | $5K |
|  | 030 | Telnet | Disable / Enforce SSH | IT | $1K |
|  | 004 | MRI XP | Maintain Isolation/FIM | ClinEng | $2K |
| **Short-term** | 013 | SNMP | Change community strings | IT | $1K |
| (7 days) | 008 | SMB Signing | Enforce GPO | Security | $1K |
|  | 009 | Guest Account | Disable | IT | $0 |
|  | 018 | Password Pol. | Enforce complexity | Security | $0 |
|  | 019 | Stale Users | Purge accounts | IT | $1K |
|  | 005 | SSH | Harden Ciphers | IT | $1K |
|  | 026 | Spooler | Harden Service | IT | $1K |
| **Medium-term** | 017 | Tomcat Info | Suppress Server Headers | IT | $1K |
| (30 days) | 015 | NAS Interface | Restrict via ACL | IT | $1K |
|  | 022/023 | Java/.NET | Patch/Upgrade | IT | $5K |
|  | 001/002 | TLS Config | Update Ciphers | Security | $1K |
|  | 011 | Lib Vuln | Update libraries | Dev | $3K |
|  | 025 | Print Server | DNS Hardening | IT | $1K |
| **Long-term** | N/A | Network Architecture | **Full Micro-segmentation** | Security | $50K |
| (90 days) | N/A | EOL Strategy | Billing Migration | IT | $30K |

### Budget Summary

* **Total Estimated Cost:** **$120,000**
* **Budget Comparison:** The total estimated cost aligns exactly with the **$120,000** annual security budget. We are operating at the limit of our fiscal capacity to address these systemic issues.
* **Deferral Strategy:** No critical security findings are currently being deferred. However, we have deferred the *full-scale replacement* of the MRI workstation (Finding 004) to the next fiscal year (beyond the 90-day window) because we have effectively mitigated the risk through physical network isolation. If this device's operational requirements change (e.g., if it needs to connect to the public internet for vendor support), we will need to reallocate the $30K planned for the Billing Server migration to cover the MRI replacement cost instead.

**Director's Note:** The "Immediate" and "Short-term" timelines require dedicated personnel shifts. The focus for the first 48 hours must be exclusively on the Ghostcat and Billing vulnerabilities to prevent data exfiltration.
