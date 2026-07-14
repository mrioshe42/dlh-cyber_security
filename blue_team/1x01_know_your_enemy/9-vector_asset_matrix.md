# 9. The Vector-to-Asset Matrix

This matrix cross-references critical attack vectors with MedDefense's most vital assets.

| Vector | EHR Database | Active Directory | Billing Server | MRI Workstation | Medical IoT | Patient Portal | O365 Email |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Phishing/Spear Phishing** | Phishing leads to clinician credentials, traversing the flat network to access EHR database ports. | Phishing leads to compromised user credentials used for lateral movement toward Domain Admin. |  |  |  |  | Phishing leads to credential harvest, granting access to the entire O365 communication suite. |
| **VPN Exploit** | VPN exploit grants network entry, allowing direct exploitation of ehr-srv-01 vulnerabilities. | VPN exploit provides initial network access, allowing scanning and eventual compromise of domain controllers. |  |  |  |  |  |
| **Default/Shared Credentials** | Harvested shared admin credentials permit direct database management console access. |  |  | Shared PACS credentials allow unauthorized remote access to the MRI imaging workstation. | Known default passwords allow unauthorized login to infusion pump interfaces. |  |  |
| **Vulnerable Software Exploit** |  |  | Unpatched Apache on billing-srv-01 allows RCE to gain control of the billing server. |  |  | Unpatched CMS on web-srv-01 allows injection attacks to compromise the public patient portal. |  |
| **Supply Chain Compromise** | Compromised MedTech maintenance access allows direct unauthorized EHR database modification. |  |  |  | Compromised vendor firmware update pushes malicious code directly to infusion pump interfaces. |  |  |
| **Insider (Malicious)** | Malicious insider uses authorized access to directly export and exfiltrate sensitive patient records. |  | Malicious insider alters financial transaction records within the billing server database. |  |  |  |  |
| **Insider (Negligent)** |  | Negligent user account compromise provides an initial entry point for attackers to traverse the AD structure. |  |  |  |  | Negligent user disables MFA or leaks credentials, exposing the organizational email account. |
| **Physical Access** |  | Physical access to server room allows direct patching/dumping of Domain Controller memory. | Physical access to server hardware enables local login and administrative control of the billing system. | Physical presence allows direct keyboard access to the legacy MRI workstation, bypassing network controls. | Physical access to infusion pumps allows direct tampering with device settings and interfaces. |  |  |

## Priority Analysis

### Top 3 Most Connected Assets

1. **EHR Database:** Its central role in clinical operations and high connectivity make it the primary target for both ransomware and malicious exfiltration.
2. **Active Directory:** Acts as the "master key" for the environment; controlling this grants the attacker total domain-wide privilege.
3. **Billing Server:** High connectivity due to its integration with financial systems and its legacy software vulnerabilities makes it a high-value, easily exploited pivot point.

### Top 3 Most Versatile Vectors

1. **Physical Access:** Grants bypass capability for almost any network control, making it the most potent vector for high-value asset compromise.
2. **Default/Shared Credentials:** Highly efficient, allowing attackers to authenticate as authorized users across diverse systems with minimal effort.
3. **Phishing/Spear Phishing:** Continues to be the most reliable, scalable, and low-cost method for securing the initial foothold required for all subsequent lateral movement.
