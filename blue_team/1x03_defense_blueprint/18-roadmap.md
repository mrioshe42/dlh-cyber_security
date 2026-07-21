# 18. The Roadmap

**Document Owner:** Sarah Park, Director of IT & Infrastructure Operations

**Target Execution Window:** August 2026 – January 2027

**Strategic Focus:** Transitioning MedDefense from a reactive, perimeter-only posture to a threat-informed defense-in-depth model aligned with NIST CSF 2.0 and CIS Controls v8.

## Month-by-Month Action Plan

### Month 1: Procurement, Perimeter Defense & Quick Wins

* **Focus:** Neutralize high-exposure external vectors, secure quick wins, and complete vendor procurement within the approved $120,000 budget.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Enforce Mandatory MFA (QW-1)** | Lead Systems Admin | M365 E3 License Verification | 100% of FortiGate VPN logins and M365 accounts enforce push/TOTP MFA; zero password-only logins logged in Active Directory. |
| **Replace Westside Router (QW-3)** | Network/Firewall Tech | FortiGate Appliance Delivery | Netgear consumer router removed; FortiGate firewall deployed at Westside Clinic with UTM rules active and site-to-site IPsec tunnel established. |
| **Disable Legacy Protocols (QW-2)** | Lead Systems Admin | Active Directory Audit | GPO pushed to disable SMBv1, Telnet, and SNMPv1/v2 across all domain controllers, servers, and managed switches. |
| **Procure EDR, SIEM & AWS Glacier** | CISO / Sarah Park | Board Budget Sign-Off ($120k) | Contracts finalized for Sophos Intercept X (540 seats), Open-Source Wazuh cloud log storage, and AWS S3 Glacier Object Lock backup repository. |

### Month 2: Core Hardware & Network Isolation

* **Focus:** Build out internal zone boundaries to stop lateral movement across server subnets, medical devices, and branch offices.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Configure Managed Switch VLANs** | Network/Firewall Tech | Switch Firmware Updates | Network split into 5 isolated VLANs (`10-Core Server`, `20-Workstation`, `30-Medical IoT`, `40-Guest`, `50-Legacy XP`). |
| **Enforce Firewall Inter-VLAN ACLs** | Network/Firewall Tech | Switch VLAN Configuration | Direct routing between `VLAN 20` (Workstations) and `VLAN 10` (EHR/Billing DBs) blocked; explicitly permitted flows locked to required ports (e.g., HTTPS 443, PACS 104). |
| **Deploy USB Blocking Policy (QW-4)** | Lead Systems Admin | Sophos Agent Staging | USB storage read/write permissions disabled via GPO/Sophos central policy across all 540 workstations; whitelisted exception process documented. |

### Month 3: Endpoint Protection & Central Logging Deployment

* **Focus:** Roll out behavioral threat blockages to all endpoints and build real-time log ingestion.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Deploy Sophos Intercept X EDR** | Lead Systems Admin | Endpoint Inventory Reconciliation | Sophos Intercept X agent installed and active on 100% of managed hosts (540 endpoints across Central Hospital, Westside, and HQ). |
| **Deploy & Configure Wazuh SIEM** | Lead Systems Admin | Cloud Storage Provisioning | Wazuh SIEM manager live; log agents deployed to all 21 servers, Domain Controllers, FortiGate firewalls, and core switches. |
| **Isolate Legacy Windows XP Host** | Clinical Engineering Lead | Inter-VLAN ACL Enforcement | Windows XP MRI host placed on `VLAN 50`; zero outbound internet egress permitted; SMB/RDP restricted strictly to PACS archive IP. |

### Month 4: Immutable Backups & Identity Hardening

* **Focus:** Guarantee rapid recovery without ransom payments and lock down elevated Active Directory accounts.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Configure AWS Glacier Object Lock** | Lead Systems Admin | AWS Account Setup & Veeam Connector | Veeam backup jobs replicating daily immutable snapshots to AWS S3 Glacier with Object Lock policy enabled (30-day retention lock). |
| **Privileged Access Management (PAM)** | Lead Systems Admin | Active Directory Audit | Domain Admin count reduced to ≤4 accounts; tier-1/tier-2 administrative separation enforced; plaintext credential files scrubbed from servers. |
| **SIEM Detection Tuning** | Lead Systems Admin / CISO | Wazuh Agent Deployment | Custom SIEM correlation rules configured to trigger email/SMS alerts for off-hours brute force, suspicious PowerShell execution, and mass file renames. |

### Month 5: Validation, Penetration Testing & Policy Rollout

* **Focus:** Test the resilience of newly implemented controls against simulated adversarial techniques.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Simulated Disaster Restore Test** | Lead Systems Admin | AWS Glacier Backup Configuration | `ehr-db-01` backup successfully restored from AWS Glacier to an isolated test environment within <4 hours; database integrity verified. |
| **Internal Penetration Test / Rule Audit** | External Security Partner | Network Segmentation & SIEM | Simulated breach attempt confirms lateral movement from `VLAN 20` to `VLAN 10` is blocked and triggers an automated Wazuh alert within 5 minutes. |
| **Roll Out Updated AUP & Training** | Sarah Park / HR Director | Executive Policy Approval | 100% of staff complete updated Security Awareness Training; digital sign-offs collected for updated Acceptable Use Policy (AUP). |

### Month 6: Optimization, Audit Hand-Off & Operational Handover

* **Focus:** Institutionalize operational workflows, finalize documentation, and transition to continuous monitoring.

| Action Item | Responsible Owner | Critical Dependencies | Completion Criteria |
| --- | --- | --- | --- |
| **Incident Response Runbook Drills** | CISO / Sarah Park | SIEM Tuning & Penetration Test | Tabletop simulation executed with executive leadership covering a simulated ransomware attack; Incident Response Plan updated with timing metrics. |
| **Final Compliance & Audit Review** | Sarah Park / Compliance Lead | All Phase 1–5 Deliverables Complete | HIPAA Security Rule compliance gap remediation report generated; residual risk register presented to the Board Audit Committee. |
| **Operational Handover to On-Call IT** | Sarah Park | Runbook Finalization | On-call rotation staff trained on Wazuh SIEM dashboard triage and initial Sophos endpoint isolation runbooks. |

## Core Technical Dependency Chain

```text
[1. Procurement & Licensing] (Month 1)
             │
             ▼
[2. Managed Switch VLAN Setup] (Month 2)
             │
             ▼
[3. Inter-VLAN Firewall ACLs] (Month 2) ──► [Medical IoT & XP Isolation] (Month 3)
             │
             ▼
[4. Sophos EDR & Wazuh SIEM Rollout] (Month 3)
             │
             ▼
[5. AWS Glacier Immutable Backups] (Month 4)
             │
             ▼
[6. Simulated Disaster Recovery Test] (Month 5)

```

1. **Procurement precedes Deployment:** Software licenses (Sophos Intercept X, AWS Glacier Storage, Wazuh Cloud) must be procured in Month 1 before agent distribution or cloud backup replication can begin in Months 3 and 4.
2. **Network Segmentation precedes Isolation:** Physical managed switches must be sliced into VLANs (Month 2) before firewall inter-VLAN access lists (ACLs) can be applied to isolate medical IoT pumps and legacy Windows XP hosts (Month 3).
3. **Log Agent Deployment precedes Alert Tuning:** Wazuh SIEM agents must be deployed and ingesting log telemetry across servers and firewalls (Month 3) before custom alert thresholds and off-hours correlation rules can be tuned (Month 4).
4. **Immutable Backup Storage precedes DR Restoration Testing:** AWS S3 Glacier Object Lock buckets must be fully configured and synchronized with Veeam (Month 4) before a live disaster recovery restore drill can be executed (Month 5).

## Critical Milestones

```text
Aug 31, 2026          Oct 31, 2026          Nov 30, 2026          Jan 31, 2027
   [M1]                  [M2]                  [M3]                  [M4]
────┼─────────────────────┼─────────────────────┼─────────────────────┼────
Perimeter Secured     Blast Radius Contained   Recovery Guaranteed   Strategy Validated

```

* **Milestone 1: Perimeter & Edge Hardened (August 31, 2026)**
* *Accomplished:* MFA enforced across 100% of VPN endpoints; Westside Clinic consumer router replaced with FortiGate enterprise firewall.
* *Measurable Success Indicator:* Zero unauthenticated or single-factor VPN authentication logs in FortiGate event history over a 14-day rolling audit window.
* **Milestone 2: Network Micro-Segmentation Live (October 31, 2026)**
* *Accomplished:* Network segmented into 5 VLANs; inter-VLAN traffic restricted via firewall ACLs; Sophos EDR deployed to 540 endpoints.
* *Measurable Success Indicator:* Automated network vulnerability scan confirms 0% direct SMB/RDP reachability between workstation subnets (`VLAN 20`) and core database subnets (`VLAN 10`).
* **Milestone 3: Threat Detection & Immutable Recovery Active (November 30, 2026)**
* *Accomplished:* Wazuh SIEM actively collecting logs from all 21 servers; Veeam replicating daily immutable snapshots to AWS S3 Glacier.
* *Measurable Success Indicator:* Successful test deletion of a local backup file demonstrates the secondary cloud copy in AWS S3 Glacier remains immutable and protected by Object Lock.
* **Milestone 4: Program Operationalized & Board Ready (January 31, 2027)**
* *Accomplished:* Full disaster recovery restore drill executed; Incident Response tabletop exercise completed with executive leadership; AUP sign-offs collected.
* *Measurable Success Indicator:* Complete recovery of `ehr-db-01` test instance from AWS Glacier within <4 hours, accompanied by a CISO report showing a 94.3% reduction in baseline $\text{ALE}$.

## Risks to Timeline & Contingency Plans

### Risk 1: Clinical Workflow Interruption During Inter-VLAN Segmentation

* **Likelihood:** High | **Impact:** High
* **Description:** Implementing strict inter-VLAN firewall ACLs in Month 2 may inadvertently block unmapped legacy ports required by PACS imaging DICOM viewers or medical IoT vital monitor telemetry, leading to clinical staff complaints or disrupted patient care.
* **Contingency Plan:**
1. Execute all inter-VLAN rule changes in **"Audit/Promiscuous Mode"** for 7 days prior to enforcement, logging all blocked traffic without dropping packets to identify hidden application dependencies.
2. Perform switch cutovers exclusively during scheduled weekend maintenance windows (Saturdays, 1:00 AM – 4:00 AM).
3. Maintain a pre-scripted, single-command firewall rollback script that restores previous routing rules within 60 seconds if clinical operations are impacted.

### Risk 2: Legacy Endpoint Agent Compatibility & Performance Degradation

* **Likelihood:** Medium | **Impact:** Medium
* **Description:** Older clinical workstations or legacy server operating systems (e.g., Windows Server 2012) may experience high CPU utilization or kernel panics when installing the Sophos Intercept X EDR agent or Wazuh SIEM log collector during Month 3.
* **Contingency Plan:**
1. Deploy EDR and SIEM agents to a pilot testing group of 20 non-critical workstations and 2 staging servers across 5 business days before attempting site-wide deployment.
2. Configure Sophos policy performance overrides (low-CPU background scanning mode) for legacy medical hosts.
3. For EOL hosts that cannot support modern EDR agents (such as the Windows XP MRI host), rely entirely on network-level micro-segmentation (`VLAN 50`) and strict firewall port isolation as the primary compensating control.
