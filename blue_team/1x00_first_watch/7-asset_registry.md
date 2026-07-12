# 7: The Asset Registry

## MedDefense Asset Registry

| Asset ID | Name | Type | Location | Owner | OS/Platform | Critical Services | Network | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A-001 | ehr-srv-01 | Server | Central/Basement | Clinical IT | Ubuntu 20.04 LTS | EHR application | 10.10.2.0/24 | Active | SSH key-only auth (only server with key auth); sole clinical system |
| A-002 | ehr-db-01 | Server | Central/Basement | Clinical IT | Ubuntu 20.04 LTS | EHR database (PostgreSQL) | 10.10.2.0/24 | Active | Accessible from entire network; no database-level ACLs; contains ~50K patient records |
| A-003 | pacs-srv-01 | Server | Central/Basement | Radiology | Windows Server 2016 | PACS imaging | 10.10.2.0/24 | Active | Shared login "raduser" bypasses accountability; hundreds of thousands of images unencrypted |
| A-004 | billing-srv-01 | Server | Central/Basement | Finance | Ubuntu 18.04 EOL | Billing/claims, payment processing | 10.10.2.0/24 | Active | COMPROMISED: Crypto-miner (Exercise 2), ransomware (Jan), SSH password auth enabled; MySQL accessible from entire network |
| A-005 | ad-dc-01 | Server | Central/Basement | IT | Windows Server 2019 | Authentication/directory | 10.10.2.0/24 | Active | Primary domain controller; centralized identity management but no MFA |
| A-006 | ad-dc-02 | Server | Central/Basement | IT | Windows Server 2019 | Authentication/directory | 10.10.2.0/24 | Active | Secondary domain controller; redundancy for AD |
| A-007 | file-srv-01 | Server | Central/Basement | IT | Windows Server 2016 | Department file shares (HR, Finance, Clinical) | 10.10.2.0/24 | Active | Unencrypted file shares; accessible from entire network |
| A-008 | print-srv-01 | Server | Central/Basement | IT | Windows Server 2012 R2 EOL | Print management | 10.10.2.0/24 | Unknown | End-of-support Oct 2023; marked [UNVERIFIED]; may be offline |
| A-009 | backup-srv-01 | Server | Central/Basement | IT | Ubuntu 22.04 LTS | Backup orchestration (Veeam) | 10.10.2.0/24 | Active | Backups to co-located NAS (same rack, same network); single point of failure for ransomware |
| A-010 | web-srv-01 | Server | Central/Basement | Marketing | Ubuntu 20.04 LTS | Public website, patient portal | DMZ | Active | Defaced Apr 5 (restored 2 hrs); portal has broken access control (Exercise 1 Incident B) |
| A-011 | ws-srv-01 | Server | Westside/Ground | Clinical IT | Windows Server 2016 | File sharing, scheduling (outpatient) | 10.10.10.0/24 | Active | Outpatient clinic local server; runs on consumer Netgear router with no firewall |
| A-012 | UNKNOWN-01 | Server | Central/Basement | Unknown | Linux 4.x | Unknown | 10.10.2.99 | Shadow IT | **UNDOCUMENTED** — Detected in network scan; web services (ports 8888, 9090); not in any IT documentation; possible Marcus/intern artifact |
| A-013 | Undocumented-Westside | Server | Westside/Ground | Unknown | Linux 5.x | Unknown | 10.10.10.200 | Shadow IT | **UNDOCUMENTED** — Port 3000 (Grafana/Node.js); someone plugged in unofficial monitoring tool; not in asset list |
| A-014 | Fortinet FortiGate 100F | Network Device | Central/Basement | IT | FortiOS unknown | Firewall, perimeter, VPN | N/A | Active | Allows ALL outbound (no egress filtering); VPN rules too permissive (ALL services from Westside/HQ); rules not audited |
| A-015 | Cisco Core Switch | Network Device | Central/Basement | IT | IOS unknown | Network core | N/A | Active | Model unknown; firmware unknown; no ACLs; supports flat network (no VLANs) |
| A-016 | Cisco Access Switches (12x) | Network Device | Central/Floors 1-6 | IT | IOS unknown | Floor-level connectivity | N/A | Active | No VLAN enforcement; flat network topology |
| A-017 | Netgear Nighthawk Router | Network Device | Westside/Ground | IT | Firmware unknown | ISP gateway, site-to-site VPN endpoint | 10.10.10.1 | Active | **INADEQUATE** — Consumer-grade equipment hosting IPSec VPN to Central; no firewall; single point of failure for Westside |
| A-018 | Ubiquiti UniFi APs (12x) | Network Device | Central/Floors 1-6 | IT | UniFi controller | Wireless (managed) | Separate SSID | Active | Guest WiFi isolation unverified; possible same VLAN as internal |
| A-019 | Workstations (Windows 10, Central) | Endpoint | Central/Floors 1-6 | Various | Windows 10 | Clinical & administrative work | 10.10.1.0/24 | Active | ~320 units; Sophos antivirus 88.1% current; RDP enabled without network restriction; high phishing target |
| A-020 | Thin Clients (ER, Central) | Endpoint | Central/ER | Clinical | Thin OS | EHR access, patient records | 10.10.1.0/24 | Active | ~60 units; limited patch baseline; SSH password auth possible |
| A-021 | Workstations (Windows 10/11, HQ/Westside) | Endpoint | HQ + Westside | Administrative, Clinical | Windows 10/11 | Finance, HR, operations | 10.10.20.0/24, 10.10.10.0/24 | Active | ~165 units (120 HQ + 45 Westside); no MDM; remote access via VPN |
| A-022 | Laptops (remote-capable) | Endpoint | HQ/Mobile | Administrative | Windows 10 | Remote access to EHR, O365, Central | VPN | Active | ~30 units; intermittent; used by executives, remote workers |
| A-023 | iPads (physician rounds) | Endpoint | Central/All floors | Clinical | iOS | EHR access, patient documentation | WiFi/Network | Active | ~25 units; MDM enrollment status unknown; not covered by Sophos |
| A-024 | Philips IntelliVue Patient Monitors | IoT/Medical | Central/Patient rooms, ICU, ER | Clinical | Proprietary firmware | Real-time vital signs | 10.10.3.0/24 (flat) | Active | ~80+ units detected in scan; accessible from entire network; HTTP/HTTPS management interfaces exposed; firmware unknown |
| A-025 | BD Alaris Infusion Pumps | IoT/Medical | Central/Inpatient units | Clinical | Firmware 12.1.2 | Medication delivery, dosage control | 10.10.3.0/24 (flat) | Active | ~120+ units detected in scan; firmware v12.1.2 has known CVEs per BD security bulletin (18 months old); network isolation NOT implemented as recommended |
| A-026 | Siemens MAGNETOM MRI Scanner | IoT/Medical | Central/Radiology | Radiology | **Windows XP Embedded EOL** | Diagnostic imaging | 10.10.1.70 | Active | **CRITICAL RISK** — Windows XP (EOL Apr 2014, 11+ years unpatched); $2.1M device; vendor certification requires XP only; cannot patch/upgrade/replace; on flat network |
| A-027 | GE Revolution CT Scanner | IoT/Medical | Central/Radiology | Radiology | Unknown OS | Diagnostic imaging | 10.10.3.0/24 (flat) | Active | OS not documented; firmware version unknown; on flat network with all workstations |
| A-028 | IP-based Nurse Call System | IoT/Comms | Central/All floors | Nursing | Proprietary firmware | Nurse paging, emergency calls | 10.10.3.0/24 (flat) | Active | Integrated with phone system; HTTP/HTTPS accessible from entire network |
| A-029 | HID Global Badge/Access System | Physical Control | Central/All doors | Security/IT | Proprietary firmware | Physical access control | 10.10.3.0/24 | Active | Partial AD integration (some doors only); server room uses generic badge (no differentiation); no audit trail |
| A-030 | NAS-01 (Synology DSM) | Data Store | Central/Basement | IT | NAS OS unknown | Backup storage (Veeam backups) | 10.10.2.41 | Active | Co-located with backup-srv-01 (same rack, same room); single point of failure; management interface (5000/5001) accessible from entire network |
| A-031 | EHR Database (PostgreSQL) | Data Store | ehr-db-01 | Clinical IT | PostgreSQL unknown | ~50,000 active patient records | 10.10.2.11:5432 | Active | No encryption at rest; no database-level access controls; accessible from entire network |
| A-032 | PACS Image Archive | Data Store | pacs-srv-01 | Radiology | Unknown format | Medical imaging (MRI, CT, X-ray) | 10.10.2.0/24 | Active | Hundreds of thousands of images; no encryption; unencrypted in transit |
| A-033 | Billing Database (MySQL) | Data Store | billing-srv-01 | Finance | MySQL unknown | Patient billing, insurance claims, payment cards | 10.10.2.15:3306 | Active | Payment card data (PCI-DSS scope unclear); accessible from entire network; ransomware-affected (Jan); crypto-miner present (Jun) |
| A-034 | O365 Tenant | Application/Cloud | Microsoft cloud | Organization-wide | SaaS | Email, OneDrive, SharePoint, Teams | Internet | Active | $432K/yr; organization-wide but shadow cloud services suspected (Google Drive, personal NAS); no DLP |
| A-035 | Patient Portal Web App | Application | web-srv-01 | Clinical IT | Unknown framework | Patient data access (lab results, records) | DMZ | Active | February breach: broken access control allowed unauthorized patient access to others' lab results (Incident B); no encryption verified |

## Reconciliation Notes

### **Shadow IT / Undocumented Assets (Found in Network Scan, NOT in Any Documentation):**

1. **UNKNOWN-01 (10.10.2.99)** — Linux server in Central servers subnet
   - **Services:** SSH (port 22), web services (ports 8888, 9090)
   - **Risk:** Complete unknown; could be Marcus's unfinished SIEM research, intern's monitoring tool, or attacker persistence
   - **Action:** Immediate investigation required; secure and document or decommission

2. **Undocumented-Westside (10.10.10.200)** — Linux device at Westside Clinic
   - **Services:** SSH (port 22), web service (port 3000 = Grafana or Node.js)
   - **Risk:** Unofficial monitoring tool deployed by staff; not managed by IT; exposes Westside via VPN to Central
   - **Action:** Determine purpose; bring under IT governance or decommission

### **Assets in Documentation NOT in Network Scan (Offline / Decommissioned):**

1. **print-srv-01 (10.10.2.31)** — Windows Server 2012 R2 marked [UNVERIFIED]
   - May be powered off, decommissioned, or unreachable during scan window
   - Status changed to "Unknown"

2. **Possible 2nd Westside server** — Referenced by Mike Torres but never confirmed
   - Not detected in scan; may not exist or offline; requires physical verification

### **Discrepancies & Critical Findings:**

| Discrepancy | Finding | Risk |
|---|---|---|
| Endpoint count (320 Central WS) | Last AD count 8 months old; actual count unknown | Unmanaged endpoint growth; Sophos coverage may be incomplete |
| iPad management | MDM status "unclear"; ~25 units not in Sophos protection | Medical data on unmanaged mobile devices; no compliance tracking |
| Network scan shows medical devices accessible | Philips monitors, BD Alaris pumps on flat network; management interfaces exposed | Life-safety devices reachable from compromised workstations; dosage modification possible |
| BD Alaris firmware v12.1.2 | Known CVEs per security bulletin 18 months old; isolation recommended but not implemented | **CRITICAL** — Patient safety risk; no compensating controls deployed |
| Firewall egress rules | Network scan confirms ALL outbound allowed (billing-srv-01 crypto-miner connected to pools undetected) | No egress filtering; attacker data exfiltration unrestricted |
| Database accessibility | MySQL (3306), PostgreSQL (5432), NAS management (5000/5001) accessible from entire network | No network segmentation; lateral movement unrestricted |

## Summary

- **Total Assets Documented:** 45+
- **Key Assets Listed:** 35 (servers, network, medical IoT, data stores, applications, endpoints)
- **Shadow IT Identified:** 2 undocumented Linux devices (10.10.2.99, 10.10.10.200)
- **End-of-Life Systems:** 3 (Windows XP MRI, Windows Server 2012 R2 print server, Ubuntu 18.04 billing server)
- **Critical Gap:** Flat network confirmed; all subnets reachable from any endpoint without restriction; medical devices on workstation network; life-safety IoT devices vulnerable to lateral movement
