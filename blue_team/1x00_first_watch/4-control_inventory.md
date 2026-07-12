# 4: The Control Landscape

## Control Registry (19 Controls)

| ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Notes |
|---|---|---|---|---|---|---|
| C-001 | FortiGate 100F Firewall | Technical | Preventive | Network perimeter | Adequate | Blocks inbound; permits ALL outbound (no egress filtering); ACLs not audited |
| C-002 | Firewall Support Contract | Administrative | Corrective | FortiGate maintenance | Adequate | $4,200/yr; enables patching and updates |
| C-003 | Sophos Endpoint Protection | Technical | Preventive | Workstations (387 devices) | Weak | 88.1% current signatures; NO coverage on servers or Linux; medical devices unprotected |
| C-004 | Password Policy (8 chars, 90-day) | Administrative | Preventive | All AD systems | Adequate | Complexity enabled; history/lockout enforced; NO MFA (except James Chen); shared accounts bypass |
| C-005 | Active Directory (AD-DC-01/02) | Technical | Preventive | Authentication & authorization | Adequate | Centralized; enables access control; no MFA; PACS shared login "raduser" weakens control |
| C-006 | Veeam Backup Software | Technical | Preventive | Data recovery | Weak | Nightly full backups; 14-day retention; stored on same NAS, network, rack as production (single point of failure) |
| C-007 | Security Guard Service | Physical | Deterrent | Main entrance (Central) | Weak | 1 guard, Mon-Fri 7 AM–7 PM only; NO nights/weekends; NO coverage at Westside/HQ |
| C-008 | Ubiquiti UniFi APs | Technical | Detective | Wireless network | Adequate | Managed APs support monitoring; guest SSID isolation unverified |
| C-009 | Guest WiFi SSID | Technical | Preventive | Visitor isolation | Weak | Separate SSID exists; network isolation not confirmed; possible same VLAN as internal |
| C-010 | Web Server DMZ | Technical | Preventive | web-srv-01 (public-facing) | Adequate | Isolated in DMZ per diagram; reduces lateral movement risk |
| C-011 | Site-to-Site VPN (Westside, HQ) | Technical | Preventive | Inter-site comms | Adequate | IPSec encrypts traffic; Westside VPN runs on consumer Netgear router (inadequate); HQ ACLs not audited |
| C-012 | O365 E3 (Microsoft) | Administrative | Preventive | Email, collaboration, cloud | Adequate | Organization-wide; built-in security; shadow cloud services not inventoried |
| C-013 | SSH Key Authentication (ehr-srv-01 only) | Technical | Preventive | Linux server auth | Weak | Key-only on ehr-srv-01; password auth STILL ENABLED on billing-srv-01, backup-srv-01 (high-value targets) |
| C-014 | HID Badge System (Partial) | Physical | Preventive | Physical access | Weak | Some doors AD-integrated; others generic badge; server room uses generic badge (no differentiation) |
| C-015 | EHR Maintenance Contract | Administrative | Corrective | EHR software patches | Adequate | $145K/yr; 4-hour SLA for critical issues; hardware patches NOT covered |
| C-016 | Incident Response (Ad Hoc) | Administrative | Corrective | Incident mitigation | Weak | NO formal IR plan; January ransomware handled by improvisation (4 days); no breach notification procedure |
| C-017 | Backup Server (Ubuntu 22.04) | Technical | Preventive | Data recovery capability | Weak | Latest OS; same weaknesses as C-006 (co-located with production) |
| C-018 | Security Awareness Training | Administrative | Preventive | All staff | Weak | 71% completion at Central, 58% at Westside; generic content; NO phishing simulations; NO role-specific training |
| C-019 | Firewall & System Logging | Technical | Detective | Network & systems | Weak | FortiGate: 30-day retention (local only); Linux: syslog (not centralized); NO automated alerting; NO SIEM |

## Control Summary Matrix

|  | **Preventive** | **Detective** | **Corrective** | **Deterrent** |
|---|---|---|---|---|
| **Technical** | C-001, C-003, C-005, C-008, C-010, C-011, C-013, C-017 | C-008, C-019 | C-002 | — |
| **Administrative** | C-004, C-012, C-018 | — | C-002, C-015, C-016 | — |
| **Physical** | C-014 | — | — | C-007 |

## Summary

- **Total Controls:** 19
- **By Category:** Technical (9), Administrative (5), Physical (1)
- **By Function:** Preventive (13), Detective (2), Corrective (4), Deterrent (1)
- **Effectiveness:** Adequate (9), Weak (10)
- **Critical Gap:** 0 Strong controls; heavily preventive; virtually no detection capability; no centralized logging/alerting

**Key Weaknesses:**
- Sophos does NOT protect servers or Linux systems
- SSH password auth still enabled on billing-srv-01 (compromised in Exercise 2)
- Firewall allows ALL outbound (enables crypto-miner to connect to pools)
- Backups co-located with production (ransomware affects both)
- NO SIEM, NO centralized logging, NO automated alerting
- Shared accounts bypass access control
- No MFA on cloud services or remote access
- NO formal incident response plan
