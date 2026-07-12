# 0: The Onboarding Packet

## 1. ORGANIZATION OVERVIEW

**MedDefense Health Systems — 3 Sites, ~2,000 Staff**

| Site | Location | Function | Staff | Details |
|---|---|---|---|---|
| **Central Hospital** | Downtown | Acute care (350 beds) | ~1,400 | 6 floors + basement (server room); Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, Admin |
| **Westside Clinic** | Suburban (12 min away) | Outpatient | ~180 | 2-story; Primary care, X-ray, ultrasound, blood work, minor procedures, physical therapy |
| **Corporate HQ** | Greenfield Park (15 min away) | Admin & IT | ~220 | 3rd floor of 5-story building; Finance, HR, Legal, Marketing, IT (12 staff); building-managed network |

**Reporting (Security-Relevant):** CEO → CISO (vacant, James Chen acting) + CFO/COO + General Counsel; James Chen (Deputy CISO, policy authority) and Sarah Park (IT Director, operations authority) are peers; **FRICTION: James has no IT operations authority.**

## 2. IT INFRASTRUCTURE IDENTIFIED

### Servers

**Central (Basement Server Room)**
- ehr-srv-01 (Ubuntu 20.04) — EHR application; SSH key-only auth (partial)
- ehr-db-01 (Ubuntu 20.04) — EHR database (PostgreSQL); ~50K patient records; accessible from entire network (no ACLs)
- pacs-srv-01 (Windows Server 2016) — PACS imaging; shared login "raduser" (no accountability)
- billing-srv-01 (Ubuntu 18.04 EOL) — Billing/claims; recurring performance issues; crypto-miner detected (Exercise 2)
- ad-dc-01/02 (Windows Server 2019) — Domain controllers; no MFA
- file-srv-01 (Windows Server 2016) — File shares (HR, Finance, Clinical)
- print-srv-01 (Windows Server 2012 R2 EOL) — Print server; [UNVERIFIED] >1 year; end-of-support Oct 2023
- backup-srv-01 (Ubuntu 22.04) — Veeam backups to co-located NAS (same room, network, rack = single point of failure)
- web-srv-01 (Ubuntu 20.04) — Public website + patient portal (DMZ)

**Westside**
- ws-srv-01 (Windows Server 2016) — Local file server + scheduling
- Undocumented server (possible) — Referenced by Mike Torres; never confirmed

**HQ**
- No on-premise servers; O365 cloud; VPN to Central

### Network Equipment

| Site | Equipment | Status |
|---|---|---|
| **Central** | Cisco core switch | Model/firmware unknown; no ACLs documented |
| **Central** | Cisco access switches (12x, 2 per floor) | Firmware unknown; flat network (no VLANs) |
| **Central** | Fortinet FortiGate 100F firewall | Support contract active; rules not audited; allows ALL outbound (no egress filtering) |
| **Central** | Ubiquiti UniFi APs (12x) | Managed; guest SSID exists but isolation unverified |
| **Westside** | Unmanaged switch | Brand unknown; no management |
| **Westside** | Netgear Nighthawk router | **INADEQUATE** — Consumer equipment; no firewall; carries site-to-site VPN; Marcus: "NOT acceptable for medical facility" |
| **HQ** | Building-managed network | Landlord controls; MedDefense visibility unknown |

### Endpoints (~540 total, count unverified; last AD count 8 months old)

- Windows 10 workstations (Central): ~320 | Westside: ~45 | HQ: ~120
- Laptops (remote-capable): ~30 | iPads (physician rounds): ~25 | Thin clients (clinical): ~60

### Medical Devices (IoT) — All on Flat Network (10.10.0.0/16)

- Philips IntelliVue monitors: ~80 (vital signs monitoring)
- BD Alaris infusion pumps: ~120 (medication delivery; firmware v12.1.2 has known CVEs per security bulletin)
- Siemens MAGNETOM MRI: 1 (Windows XP Embedded, EOL Apr 2014; cannot patch; 6 yrs into 12-yr lifespan)
- GE Revolution CT scanner: 1 (OS unknown; firmware unknown)
- IP-based nurse call system: 1 (integrated with phone)
- HID Global badge readers: Multiple (partial AD integration; server room uses generic badge)

### Managed Services

| Service | Provider | Cost/Yr | Status |
|---|---|---|---|
| Endpoint Protection | Sophos | $18K | Deployment currency unverified; no server/Linux coverage |
| Backup Software | Veeam | $8.5K | Local NAS only; no cloud replication |
| Firewall Support | Fortinet | $4.2K | Critical for patching |
| Email/Collaboration | O365 E3 | $432K | Organization-wide; shadow cloud services suspected |
| WiFi License | Ubiquiti | Free | Managed APs (Central only) |
| EHR Maintenance | MedTech | $145K | Software updates only; 4-hr SLA critical; no hardware patches |
| Physical Guard | ClearView | $96K | 1 guard, main entrance only, Mon-Fri 7 AM–7 PM; no coverage nights/weekends/Westside/HQ |

## 3. DATA AND SERVICES

### Data Handled

| Data Type | Classification | System | Users | Notes |
|---|---|---|---|---|
| Patient medical records (PHI) | Restricted | EHR (ehr-db-01) | Clinicians, physicians, nurses | ~50K active patients; diagnoses, medications, lab results |
| Medical imaging (PHI) | Restricted | PACS (pacs-srv-01) | Radiologists, clinicians, surgeons | MRI, CT, X-ray images; unencrypted |
| Patient billing/insurance (PHI + financial) | Restricted | billing-srv-01 | Finance, billing staff | Names, SSNs, insurance, payment cards; ransomware-affected (Jan); crypto-miner detected (Jun) |
| Employee HR/payroll | Confidential | File shares, O365 | HR, Finance, Executives | Salaries, contracts, performance reviews |
| System credentials/API keys | Restricted | AD, SSH configs, servers | IT/System admins | Weak protection; no centralized secrets management |
| Audit logs/access records | Confidential | Firewall, servers, workstations | IT staff | Rarely reviewed; no centralized logging |
| Patient portal data | Restricted | web-srv-01 | Patients (external, internet-facing) | Lab results, appointments, medical records; broken access control (Feb incident) |

### Critical Services (Outage Impact)

- **EHR (>4 hrs):** Paper records fallback; CMS reportable incident
- **PACS (>2 hrs):** Imaging halted; surgeries delayed
- **Medication delivery (any):** Manual administration fallback; patient safety risk
- **Patient monitoring (any):** Manual monitoring fallback; ICU/ER compromised
- **Billing (>1 day):** Claims backlog; revenue disrupted
- **Nurse call system (any):** Workflow disrupted; patient safety risk
- **Network/WiFi (>30 min):** EHR inaccessible; workstations disconnected

## 4. KNOWN UNKNOWNS

### Incomplete/Unverified Assets

- **print-srv-01:** Marked [UNVERIFIED] in asset list; may be decommissioned or running unpatched OS
- **Possible 2nd Westside server:** Referenced by Mike Torres; never physically confirmed
- **Westside WiFi AP:** Vendor/model/firmware unknown
- **Cisco equipment (all):** Model numbers, firmware versions not documented
- **Fortinet firewall:** Firmware version unknown; patch status unknown
- **Netgear router (Westside):** Firmware/patch status unknown; no update schedule
- **HQ network:** Managed by building landlord; MedDefense has zero visibility into firewall/routing/VLAN config

### Contradictions/Ambiguities

| Item | Contradiction | Risk |
|---|---|---|
| **Endpoint count** | Asset list ~540; Marcus notes "nobody has complete count; 8 months old" | Actual inventory unknown; vulnerability scan scope unclear |
| **Backup isolation** | NAS co-located with production servers in same room/network/rack | Ransomware affects both production and backup simultaneously; no recovery option |
| **WiFi segmentation** | Asset list shows separate SSID; Marcus: "not convinced it's actually isolated" | Guest network may not be VLAN-isolated; unconfirmed |
| **HQ VPN** | Asset list "properly configured"; Marcus "haven't audited ACLs" | Access rules unknown; over-permissive access possible |
| **MFA** | Policy: "recommended but not required"; Marcus: "nowhere except James's personal account" | Only 1 person has MFA; asymmetric security posture |
| **Print server** | Listed active; EOL Oct 2023; Marcus: "nobody seems to care" | Receives no patches; compliance debt; actual status unclear |

### Critical Documentation Gaps

| Gap | Impact | Evidence |
|---|---|---|
| **No formal vulnerability assessment** | Unknown patch status across infrastructure; no baseline | Marcus: "I haven't gotten to formal vulnerability assessment" |
| **No HIPAA compliance audit** | Unknown regulatory compliance status | Marcus: "HIPAA never formally assessed. Legal says compliant but no evidence" |
| **No incident response plan** | Jan ransomware handled ad-hoc over 4 days with no procedures | Marcus: "No formal IR plan. Response was improvised" |
| **No business continuity/DR plan** | No recovery procedure if power outage >20 min UPS runtime | Marcus: "No BCP. No DRP. If Central loses power, no documented procedure" |
| **No backup testing** | Recovery time/completeness unknown; RTO/RPO not defined | No mention of restore testing or validation |
| **Cloud inventory incomplete** | O365 confirmed; departments suspected using shadow services | Marcus: "O365 is main one but I suspect individual departments use others" |
| **Antivirus coverage unclear** | Sophos deployed but current status on all machines unknown | Marcus: "Sophos deployed but don't know if current on all machines" |
| **Threat landscape not analyzed** | No assessment of which threat actors target healthcare | Marcus: "Who targets hospitals? Started researching but didn't finish" |
| **Network segmentation not implemented** | Flat network; Marcus escalated; response "planned for next fiscal year" 4 months ago | Marcus: "Flat network... I brought it up. She said planned for next fiscal year. That was 4 months ago" |

## Summary

**What We Know:**
- 3 sites, ~2,000 staff, ~10 servers, ~540 endpoints, ~200 medical IoT devices
- Organizational structure: CISO vacant; James Chen (policy) + Sarah Park (IT ops) as peers
- Core infrastructure: FortiGate firewall, Cisco switches, O365, Sophos, Veeam backups
- Critical services: EHR, PACS, billing, patient monitoring, medication delivery
- Annual security spend: ~$764K

**What We Don't Know:**
- Exact asset counts (inventory incomplete)
- Firewall rules, VPN ACLs, network segmentation status
- Firmware/patch status on all equipment
- HIPAA compliance baseline
- Incident response procedures
- Full cloud service inventory (shadow IT unknown)
- Backup recovery testing results

**Critical Issues Identified:**
-  Flat network (no VLANs) = unrestricted lateral movement
-  Backup NAS co-located with production (single point of failure)
-  Westside has consumer router + no firewall (remote site vulnerable)
-  Medical devices on workstation network (patient safety risk)
-  Zero network monitoring/detection capability
-  CISO vacant; organizational authority unclear
