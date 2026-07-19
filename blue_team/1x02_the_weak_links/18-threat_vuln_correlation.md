# 18. The Threat-Vulnerability Correlation

### Threat-Vulnerability Correlation Matrix

| Finding [ID] | Threat Actor(s) | Vector | Kill Chain | Scenario | Gap |
| --- | --- | --- | --- | --- | --- |
| **031** (Ghostcat) | RaaS (BlackReef) | Web Exploit | #1 (Ransomware) | Initial Access | WAF/Patching |
| **007** (LDAP Relay) | RaaS / APT41 | Internal/Lateral | #1 (Ransomware) | DC Compromise | Net-04 (Flat Network) |
| **010** (Alaris Pump) | RaaS (Sabotage) | Default Credentials | #2 (IoT Sabotage) | Patient Harm | IAM-04 (Creds) |
| **004** (MRI XP) | APT Groups | Supply Chain | #5 (MRI Persistence) | Long-term Espionage | Sys-01 (Legacy OS) |
| **003** (Billing DB) | RaaS (Double Extortion) | App Exploit | #3 (EHR Data Exfil) | Data Exfiltration | SEC-02 (DLP) |
| **016** (Philips Mon) | Opportunistic | Network Scanning | #2 (IoT Sabotage) | Espionage | Net-04 (Flat Network) |
| **024** (IoT Gateway) | RaaS | Web Interface | #2 (IoT Sabotage) | Lateral Movement | Net-04 (Flat Network) |
| **027** (Billing Agent) | RaaS | Malware | #1 (Ransomware) | Persistence/Staging | Gap-002 (No SIEM/EDR) |

### Critical Analysis: The Force Multiplier

While the **Alaris Pump (Finding 010)** represents the most immediate, localized threat to human life, the **LDAP Relay vulnerability on the Domain Controller (Finding 007)** is the most damaging vulnerability from a holistic organizational perspective. Its exploitation does not just compromise a single system; it serves as the "master key" for the entire MedDefense infrastructure. By exploiting this, an attacker gains Domain Admin privileges, allowing them to bypass all other security controls, deploy ransomware across the flat network (Kill Chain #1), disable medical device monitoring, and exfiltrate billing/EHR data simultaneously. It is the ultimate force multiplier because it converts an isolated breach into a total operational collapse, granting the attacker the ability to dictate the scope of the disaster and paralyze the hospital's clinical and administrative response capabilities.
