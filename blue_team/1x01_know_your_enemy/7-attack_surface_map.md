# 7. The Attack Surface

## Section 1: External Surface (Internet-Facing)

| Entry Point | Asset | Protection | Gap Reference |
| --- | --- | --- | --- |
| **Patient Portal** | `web-srv-01` | WAF (partial) | Web-01 (Unpatched CMS) |
| **VPN Endpoints** | FortiGate VPN | MFA (User-level) | Net-01 (Unpatched CVEs) |
| **Email Infrastructure** | O365 E3 | Entra ID MFA | IAM-02 (Phishing sensitivity) |
| **Public Website** | `web-srv-02` | None | Web-02 (Lack of integrity monitoring) |
| **DNS Infrastructure** | External DNS | Standard ISP | Net-03 (Lack of DNSSEC) |

## Section 2: Internal Surface (Post-Compromise)

Due to the identified **flat network architecture**, internal movement is largely unrestricted.

* **MySQL (billing-srv-01):** Port 3306 accessible network-wide. In a flat network, this allows any compromised workstation to query billing databases directly.
* **PostgreSQL (ehr-db-01):** Port 5432 accessible network-wide. This exposes the core EHR database to unauthorized internal querying or brute-force attempts.
* **Management Interfaces:** NAS, FortiGate admin, and IoT web interfaces are exposed on default ports. These are prime targets for credential harvesting and lateral movement.
* **Legacy Systems:** Windows XP (MRI workstations) and Server 2012 R2 represent significant unpatched exposure points that facilitate rapid exploit propagation within the flat environment.
* **Default Credentials:** PACS and various medical IoT devices utilize factory-default credentials, which, combined with the lack of VLAN segmentation, allows an attacker to pivot across the clinical network easily.

## Section 3: Human Surface

| Role | Access Level | Vulnerability Drivers | Control/Training Gap |
| --- | --- | --- | --- |
| **Clinical Staff** | High (EHR) | Time-sensitive clinical environment | TRN-01 (Low training completion) |
| **Reception** | Physical | High traffic, public-facing | PHI-01 (Physical access control) |
| **IT Staff** | Administrative | Alert fatigue, resource constraints | IAM-05 (Excessive privileges) |
| **Executives** | Strategic | High-value targets for BEC | IAM-03 (Executive training gap) |
| **Contractors** | Variable | Outside organizational oversight | VDR-01 (Third-party risk) |

## Surface Assessment Summary

The **Internal Surface** represents the greatest risk to MedDefense today. While external entry points provide the initial foothold, the flat network architecture ensures that once an attacker is inside, they have virtually unhindered access to critical assets like the EHR database and administrative interfaces. The absence of effective internal segmentation means there are no "firebreaks" to stop the propagation of ransomware or data exfiltration, turning every minor endpoint compromise into a potential organizational catastrophe.
