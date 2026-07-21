# 14. The Segmentation Architecture

## Segmentation Architecture & Zone Design

This architecture transforms MedDefense Health Systems from a flat `/16` broadcast domain into a zero-trust, microsegmentated topology enforced by enterprise firewalls and 802.1Q switch trunking.

### Part 1: Zone Definition

| Zone Name | Subnet / VLAN | Included Systems | Allowed Outbound Connections | Allowed Inbound Connections |
| --- | --- | --- | --- | --- |
| **1. Server Zone** | `10.100.10.0/24` (VLAN 10) | EHR DB (`ehr-db-01`), EHR App (`ehr-srv-01`), Active Directory DCs, Billing, File Server | Core Management (VLAN 40) for updates/logging; AWS S3 (Backup traffic via HTTPS). | **VLAN 20** (EHR ports 443/8443); **VLAN 30** (PACS/DICOM 104); **VLAN 40** (Admin RDP/SSH/WinRM). Explicitly **DENIED** from VLAN 50. |
| **2. Clinical Workstation Zone** | `10.100.20.0/23` (VLAN 20) | 280 Clinical Workstations, Nursing Station Terminals, Physician Laptops | **VLAN 10** (EHR App, AD Auth/DNS); Internet (Port 80/443 via Web Proxy); M365 Cloud Services. | **VLAN 40** (Remote Management / EDR Agents). Inter-workstation communication is **BLOCKED**. |
| **3. Medical Device Zone** | `10.100.30.0/23` (VLAN 30) | BD Alaris Infusion Pumps, Siemens MRI Workstation, Patient Monitors, PACS Archival | **VLAN 10** (PACS DICOM Port 104 to `ehr-srv-01` only). **NO INTERNET ACCESS.** | **VLAN 40** (Management Jump Host only). Inter-device traffic **BLOCKED** except explicit telemetry bridges. |
| **4. Management Zone** | `10.100.40.0/24` (VLAN 40) | IT Admin Workstations, SIEM Server (Wazuh), FortiGate Admin Interfaces, Backup Appliance | **ALL ZONES** (Restricted to SSH, RDP, HTTPS, WinRM, Syslog ports); Internet (Threat Intelligence feeds). | Explicitly **DENIED** from all non-management zones. Requires MFA + PAM Jump Server access. |
| **5. Guest / IoT Zone** | `10.100.50.0/24` (VLAN 50) | Visitor Wi-Fi, HVAC Control Panels, Vending Machines, Personal BYOD Devices | Direct Egress to Internet (Port 80/443, DNS via Cloudflare `1.1.1.1`). | **NONE.** Completely isolated. No inbound traffic permitted from any zone. |

### Part 2: Critical Firewall Rules

```text
# Rule 1: Allow Active Directory Authentication & Domain Services
Rule 101: Source: [VLAN 20: Clinical Workstations] ──> Destination: [VLAN 10: Server Zone (AD DCs)] 
          Ports: [UDP/TCP 53 (DNS), TCP 88 (Kerberos), TCP 389/636 (LDAP/S)] ──> ACTION: ALLOW

# Rule 2: Allow EHR Web Application Access
Rule 102: Source: [VLAN 20: Clinical Workstations] ──> Destination: [VLAN 10: EHR Server (ehr-srv-01)] 
          Ports: [TCP 443, TCP 8443] ──> ACTION: ALLOW

# Rule 3: Allow Medical Device DICOM Telemetry
Rule 103: Source: [VLAN 30: Medical Device Zone] ──> Destination: [VLAN 10: PACS/EHR Server] 
          Ports: [TCP 104 (DICOM), TCP 2762] ──> ACTION: ALLOW

# Rule 4: Dedicated IT Administrative Management
Rule 104: Source: [VLAN 40: Management Jump Host] ──> Destination: [ALL ZONES] 
          Ports: [TCP 22 (SSH), TCP 3389 (RDP), TCP 5985/5986 (WinRM)] ──> ACTION: ALLOW (Logged)

# Rule 5: Centralized SIEM Audit Logging Egress
Rule 105: Source: [VLAN 10, 20, 30, 50] ──> Destination: [VLAN 40: Wazuh SIEM Server] 
          Ports: [UDP 514 (Syslog), TCP 1514/1515 (Wazuh Agent)] ──> ACTION: ALLOW

# Rule 6: Isolated Internet Egress for Guest/IoT
Rule 106: Source: [VLAN 50: Guest/IoT Zone] ──> Destination: [WAN / Internet Gateway] 
          Ports: [TCP 80, TCP 443, UDP 53] ──> ACTION: ALLOW

# Rule 7: DENY Guest Zone Access to Internal Infrastructure (Inter-VLAN Block)
Rule 201: Source: [VLAN 50: Guest/IoT Zone] ──> Destination: [VLAN 10, 20, 30, 40 Internal Subnets] 
          Ports: [ANY] ──> ACTION: DENY (Log & Alert)
          *Prevents visitor devices or compromised smart HVAC panels from probing or attacking hospital servers.*

# Rule 8: DENY Workstation-to-Workstation Lateral Movement (Peer-Isolation)
Rule 202: Source: [VLAN 20: Clinical Workstations] ──> Destination: [VLAN 20: Clinical Workstations] 
          Ports: [ANY (SMB 445, RDP 3389, RPC 135)] ──> ACTION: DENY (Log & Alert)
          *Disrupts automated lateral ransomware propagation (e.g., PsExec/WMI/EternalBlue) between workstations.*

# Rule 9: DENY Direct Internet Egress for Medical Devices
Rule 203: Source: [VLAN 30: Medical Device Zone] ──> Destination: [WAN / Internet Gateway] 
          Ports: [ANY] ──> ACTION: DENY (Log & Alert)
          *Prevents compromised medical devices (pumps, MRI) from connecting to external C2 servers or downloading malware.*

# Rule 10: Default Implicit Deny
Rule 999: Source: [ANY] ──> Destination: [ANY] 
          Ports: [ANY] ──> ACTION: DENY

```

### Part 3: Kill Chain Disruption Analysis

#### Break-Point Walkthrough: Ransomware Encrypts EHR (Kill Chain #1)

```text
[Step 1: External VPN Exploit] ──> [Step 2: Foothold via Cobalt Strike] 
                                                  │
                                                  ▼
                                    [Step 3: Lateral Movement] 
                                                  │
                                     SEGMENTATION BREAK-POINT 
                                                  │
                                                  ▼
                               [Step 4: Objective Execution (Ransomware)]

```

* **Step 1 (Initial Access):** Attacker exploits FortiGate VPN and gains shell access on a workstation in `VLAN 20`.
* **Step 2 (Foothold):** Cobalt Strike beacon establishes outbound C2 via HTTPS proxy.
* **Step 3 (Lateral Movement - **BROKEN**):**
* *Without Segmentation:* The attacker scans the flat `/16` subnet, discovers `ehr-db-01` (`10.100.10.5`), and executes remote PowerShell scripts over SMB (Port 445) and RDP (Port 3389) across all workstations and servers.
* *With Segmentation:* **Firewall Rule 202** blocks workstation-to-workstation traffic, preventing the beacon from pivoting across other endpoints. **Firewall Rule 999/Rule 101** blocks direct SMB/RDP/RPC connections from `VLAN 20` to `VLAN 10` servers. The attacker cannot reach the Domain Controller or `ehr-db-01` directly over administrative ports. The ransomware attack is isolated to a single workstation.

#### Top 5 Kill Chains Disruption Rate: **80% Disrupted**

Network segmentation directly breaks **4 out of the top 5 kill chains**:

1. **Kill Chain #1 (Ransomware EHR Encryption):** **DISRUPTED at Step 3.** Segmentation blocks lateral SMB/RDP movement from workstations to core database servers.
2. **Kill Chain #2 (Medical IoT Sabotage):** **DISRUPTED at Step 3.** **Rule 203** isolates infusion pumps in `VLAN 30`, preventing compromised workstations or guest devices from scanning or altering pump configurations.
3. **Kill Chain #3 (EHR Data Exfiltration):** **PARTIALLY MITIGATED at Step 3.** Egress firewall rules and VLAN controls force database queries through monitored proxy paths, alerting SIEM to anomalous export volumes.
4. **Kill Chain #4 (BEC and Identity Theft):** **NOT DISRUPTED.** Cloud-based email phishing bypasses local network segmentation; reliance remains on MFA and security awareness.
5. **Kill Chain #5 (MRI System Persistence):** **DISRUPTED at Step 3.** Unsupported Windows XP MRI in `VLAN 30` is completely isolated from `VLAN 20` workstations and `VLAN 10` core infrastructure, preventing internal lateral pivoting.
