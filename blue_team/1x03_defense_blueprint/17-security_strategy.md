# 17. The Security Strategy Document

**To:** Board of Directors & Executive Management, MedDefense Health Systems

**From:** Chief Information Security Officer (CISO)

**Date:** July 21, 2026

**Subject:** FY26–FY27 Comprehensive Security Strategy & Investment Plan

## 1. Executive Summary

MedDefense Health Systems operates at a **High/Critical residual risk posture**, driven by a flat internal network, unpatched edge devices, and lack of real-time detection across clinical and administrative systems. Three security incidents in the past six months—including a 4-day operational outage from ransomware and a patient portal data exposure—confirm that existing defenses are insufficient against modern threat actors like the BlackReef Ransomware-as-a-Service (RaaS) group.

To establish operational resilience without disrupting patient care, MedDefense has adopted a threat-informed security strategy built on the **NIST Cybersecurity Framework (CSF 2.0)** and prioritized using **CIS Critical Security Controls (v8)**. This strategy shifts MedDefense from a reactive, perimeter-only posture to a defense-in-depth model focused on containment and rapid recovery.

We request approval for a targeted **$120,000 baseline capital investment**, which will reduce MedDefense’s Annualized Loss Expectancy ($\text{ALE}$) by **$4,659,234**—delivering a **$4,539,234 net financial return** in risk reduction.

```text
[Baseline Annual Exposure: $4.94M ALE] ──► [FY26 Security Controls ($120k Investment)] ──► [Residual Exposure: $280k ALE]
                                                                                            │
                                                                                            └──► 94.3% Risk Reduction

```

### Top 3 Priority Strategic Actions

1. **Enforce Zero-Trust Network Segmentation (VLANs & Firewalls):** Isolate core databases, medical IoT (infusion pumps/monitors), and branch offices to stop ransomware propagation.
2. **Mandate Multi-Factor Authentication (MFA) & EDR:** Eliminate 90% of initial access vectors by securing VPNs, administrative identities, and 540+ endpoints with Sophos Intercept X.
3. **Establish Offsite Immutable Backups (AWS S3 Glacier Object Lock):** Guarantee recovery within 48 hours without paying extortion fees during a cyber incident.

## 2. Governance Framework

### Framework Rationale & Target Alignment

MedDefense has selected **NIST CSF 2.0** as its overarching governance framework due to its explicit alignment with healthcare regulatory mandates (HIPAA Security Rule) and risk management standards. Tactical implementation is driven by **CIS Critical Security Controls v8 Implementation Group 1 (IG1)** to maximize hygiene with minimal operational complexity.

#### NIST CSF Profile Transition (T1)

* **Current Profile (Tier 1 - Partial):** Reactive incident handling, unmonitored internal movement, ad-hoc patching, non-existent logging, and siloed asset oversight.
* **Target Profile (Tier 3 - Repeatable / Risk-Informed):** Centralized log aggregation via Open-Source SIEM, automated endpoint threat blockages, enforced network micro-segmentation, and documented risk acceptance governance.

#### CIS Controls Maturity Scorecard (T2)

```text
CIS Control 06: Access Control             [████████████░░░░] 75% (Target: MFA Enforced)
CIS Control 12: Network Infrastructure     [██████████████░░] 85% (Target: VLAN Isolated)
CIS Control 08: Audit Log Management       [██████████░░░░░░] 60% (Target: Wazuh SIEM)
CIS Control 10: Malware Defenses           [████████████████] 100% (Target: Intercept X)
CIS Control 11: Data Recovery              [████████████████] 100% (Target: Immutable 3-2-1)

```

### Governance Structure & Roles

```
                      ┌────────────────────────────────────────┐
                      │          Board of Directors            │
                      │   Risk Appetite & Capital Oversight    │
                      └───────────────────┬────────────────────┘
                                          │
                      ┌───────────────────▼────────────────────┐
                      │    Chief Executive Officer (CEO)       │
                      │  Executive Strategy & Policy Approval   │
                      └───────────────────┬────────────────────┘
                                          │
       ┌──────────────────────────────────┴──────────────────────────────────┐
       │                                                                     │
┌──────▼────────────────────────────────┐                         ┌──────────▼───────────────────────────┐
│ Chief Information Security Officer    │                         │ Chief Operating / Medical Officer    │
│ Security Implementation & Incident IR │                         │ Operational Continuity & Workflow    │
└──────┬────────────────────────────────┘                         └──────────┬───────────────────────────┘
       │                                                                     │
       ├──────────────────────────────────┬──────────────────────────────────┤
       │                                  │                                  │
┌──────▼─────────────────┐     ┌──────────▼──────────────┐        ┌──────────▼───────────────────────────┐
│ Senior Systems Admin   │     │ Network/Firewall Tech   │        │ Clinical Engineering Lead            │
│ EDR, SIEM & IAM Ops    │     │ VLANs, ACLs & Edge VPN  │        │ Medical IoT (IoMT) Safety            │
└────────────────────────┘     └─────────────────────────┘        └──────────────────────────────────────┘

```

## 3. Quantitative Risk Analysis

### Top 5 Risks by Annualized Loss Expectancy ($\text{ALE}$)

Quantitative risk modeling demonstrates that catastrophic loss is concentrated in ransomware encryption and data exfiltration scenarios:

$$\text{ALE} = \text{Single Loss Expectancy (SLE)} \times \text{Annualized Rate of Occurrence (ARO)}$$

| Risk ID | Risk Description | Asset Impacted | Baseline SLE | Baseline ARO | Baseline ALE | Residual ALE (Post-Control) |
| --- | --- | --- | --- | --- | --- | --- |
| **RISK-01** | Ransomware EHR Database Encryption | EHR Database (`ehr-db-01`) | $1,800,000 | 0.85 | **$1,530,000** | $103,216 |
| **RISK-02** | Exfiltration of Patient PHI (Data Theft) | Billing & PACS Systems | $1,200,000 | 0.70 | **$840,000** | $120,000 |
| **RISK-03** | Negligent Insider Data Leakage | Cloud Storage / Email | $350,000 | 1.20 | **$420,000** | $105,000 |
| **RISK-04** | Medical IoT Device Disruption | Alaris Pumps / Monitors | $250,000 | 0.35 | **$87,500** | $8,750 |
| **RISK-05** | Legacy System Exploitation (MRI Host) | Windows XP Workstation | $175,000 | 0.50 | **$87,500** | $8,750 |

### Risk Appetite Statement

MedDefense operates with a **Moderate Risk Appetite** for general administrative IT operations, recognizing that budget limits require balancing security expenditure against clinical priorities. However, MedDefense maintains **Zero Tolerance (Zero Appetite)** for risks impacting patient safety, life-support hardware, or systemic PHI exfiltration.

> **Governance Threshold:** Any residual risk scenario exceeding **$100,000 in SLE** or posing a threat to human life cannot be accepted by technical leads and requires formal sign-off from the CEO and Board Audit Committee.

## 4. Control Strategy & Budget Allocation

### Cost-Benefit Analysis & Budget Selection

Evaluating proposed controls against financial risk reduction confirms that allocating the $120,000 annual security budget across Controls 1 through 6 captures maximum return on investment while remaining within capital constraints:

```
Total Capital Budget: $120,000
┌─────────────────────────────────────────────────────────┬──────────────┐
│ Control / Asset Focus                                   │ Cost         │
├─────────────────────────────────────────────────────────┼──────────────┤
│ 1. Control 2: MFA Deployment (M365 E3 Integration)      │ $10,000      │
│ 2. Control 1: Network Segmentation (Switches/VLANs)     │ $25,000      │
│ 3. Control 3: Enterprise SIEM (Wazuh Open-Source)       │ $36,000      │
│ 4. Control 5: EDR Upgrade (Sophos Intercept X)          │ $30,000      │
│ 5. Control 4: Immutable Backups (AWS Glacier Lock)      │ $15,000      │
│ 6. Control 6: Westside Clinic Enterprise Firewall       │ $4,000       │
└─────────────────────────────────────────────────────────┴──────────────┘
Remaining Budget: $0

```

| Proposed Control | CIS Ref | Cost | ALE Reduction | Net Value | Decision |
| --- | --- | --- | --- | --- | --- |
| **Control 2: MFA Deployment** | CIS 6 | $10,000 | $2,041,875 | **$2,031,875** | **Funded** |
| **Control 1: Network Segmentation** | CIS 12 | $25,000 | $1,551,185 | **$1,526,185** | **Funded** |
| **Control 3: Enterprise SIEM (Wazuh)** | CIS 8 | $36,000 | $741,000 | **$705,000** | **Funded** |
| **Control 5: EDR Upgrade (Intercept X)** | CIS 10 | $30,000 | $191,458 | **$161,458** | **Funded** |
| **Control 4: Offsite Immutable Backups** | CIS 11 | $15,000 | $103,216 | **$88,216** | **Funded** |
| **Control 6: Westside Clinic Firewall** | CIS 4 | $4,000 | $31,500 | **$27,500** | **Funded** |
| *Control 8: Dedicated Medical NAC* | CIS 12/13 | $90,000 | $83,475 | **-$6,525** | Excluded |
| *Control 7: 24/7 Managed SOC (MSSP)* | CIS 13 | $180,000 | $120,000 | **-$60,000** | Excluded |

### Quick Wins for Immediate Execution (First 30 Days)

* **QW-1:** Enforce MFA on all external FortiGate VPN logins and M365 accounts ($0 software cost, leveraging M365 E3 licenses).
* **QW-2:** Disable unused legacy protocols (SMBv1, Telnet, SNMPv1/v2) across domain controllers and core switches.
* **QW-3:** Deploy consumer-router replacement at Westside Clinic with FortiGate enterprise firewall ($4,000).
* **QW-4:** Enforce USB storage blocking on all 540 endpoints via centralized Sophos policy.

---

## 5. Architecture Recommendations

### Network Segmentation Architecture

MedDefense is transitioning from a flat network to a segmented micro-zone architecture to contain breach radii:

```text
                               ┌────────────────────────────────┐
                               │  External Internet / VPN Gateway│
                               └───────────────┬────────────────┘
                                               │
                                 ┌─────────────▼─────────────┐
                                 │ Perimeter FortiGate FW    │
                                 └─────────────┬─────────────┘
                                               │
  ┌──────────────────────┬─────────────────────┼─────────────────────┬──────────────────────┐
  │ VLAN 10              │ VLAN 20             │ VLAN 30             │ VLAN 40              │ VLAN 50
┌─▼──────────────────┐ ┌─▼─────────────────┐ ┌─▼─────────────────┐ ┌─▼──────────────────┐ ┌─▼──────────────────┐
│ Enterprise Core    │ │ Clinical Stations │ │ Medical Devices   │ │ Guest & Public Wifi│ │ Isolated Legacy    │
│ EHR, Billing, AD   │ │ Workstations, PC  │ │ Pumps, Monitors   │ │ Patient Internet   │ │ Windows XP MRI     │
└────────────────────┘ └───────────────────┘ └───────────────────┘ └────────────────────┘ └────────────────────┘

```

### Kill Chain Disruption Analysis

## 6. Policy Foundation

### Acceptable Use Policy (AUP) Governance Summary

The updated Acceptable Use Policy (AUP) establishes strict operational baselines for all staff, clinical faculty, and contractors:

* **Credential Sharing:** Zero tolerance for shared logins (e.g., historical `raduser` shared accounts). Individual Active Directory logins are required for audit trails.
* **Shadow IT & Personal Devices:** Strictly prohibits unmanaged personal network attached storage (NAS) drives or cloud storage accounts on clinical subnets.
* **Remote Access:** All remote access must route through encrypted FortiGate VPN tunnels enforced with MFA. Personal devices are barred from direct VPN access without endpoint compliance validation.

### Policy Development Roadmap

1. **Q1 FY27:** Identity & Access Management (IAM) Policy (Auto-offboarding SLA linked to HR systems).
2. **Q2 FY27:** Incident Response & Data Retain Policy (Formal breach handling workflow).
3. **Q3 FY27:** Third-Party Vendor Risk Management Policy (Mandatory vendor security reviews).
4. **Q4 FY27:** Data Classification & Retention Policy (Automated PHI labeling and egress rules).

## 7. Residual Risk Assessment & Red Team Analysis

### Red Team Findings (Simulated BlackReef Affiliate Strategy)

An adversarial red team assessment evaluated the post-implementation security strategy to identify remaining vulnerabilities:

```text
[Initial Access: AiTM Phishing Proxy] ──► [Hijack Authenticated M365 Session]
                                                        │
                                                        ▼
[Pivoting: Jump to EOL Windows XP MRI Host] ◄── [Avoid Sophos EDR via Native Land-Tools]
                   │
                   ▼
[Exfiltrate PHI via HTTPS Port 443 at 2:00 AM] ──► [Defeated Internal SIEM During Weekend Dwell Window]

```

* **Exposed Vulnerability:** Because **24/7 Managed SOC (Control 7)** was deferred due to negative net return ($180k cost vs $120k ALE reduction), internal Wazuh SIEM alerts generated off-hours rely on IT staff reviewing dashboards during business hours. An attacker executing low-and-slow data exfiltration at 2:00 AM on a Saturday maintains a 48-hour dwell window before manual review occurs.

### Approved Accepted Risks (Formal Risk Register)

1. **Windows XP MRI Workstation (`RISK-05`):** Accepted by COO for 18 months until the $2.1M scanner lease expires. **Compensating Control:** Micro-segmentation on `VLAN 50` with outbound internet blocking.
2. **Absence of 24/7 Managed SOC (`RISK-01`):** Accepted by CEO/CFO due to cost efficiency constraints. **Compensating Control:** Automated Sophos Intercept X execution prevention and automated SIEM email escalation.
3. **Physician Shadow IT / Personal File Share (`RISK-03`):** Accepted by CMO/CIO to balance workflow needs. **Compensating Control:** USB blocking via EDR and periodic automated scanning.

### Year 2 (FY27) Investment Priorities

* **Priority #1:** Integrate Co-Managed 24/7 Detection & Response (MDR) to close off-hours monitoring gaps ($60k–$80k).
* **Priority #2:** Implement automated HR-to-AD identity offboarding integrations to eliminate ghost contractor accounts.
* **Priority #3:** Upgrade/replace EOL Billing server operating systems.

## 8. Implementation Roadmap

```text
Phase 1: Months 1-2 (Quick Wins & Procurement)
- Procure Sophos, FortiGate Westside, and AWS Glacier
- Enforce MFA across VPN & M365
- Isolate Westside Clinic via Hardware Firewall

Phase 2: Months 3-4 (Core Controls Deployment)
- Deploy Sophos Intercept X to 540 endpoints
- Implement core switch VLAN segmentation (VLANs 10-50)
- Deploy Wazuh Open-Source SIEM & configure log ingestion

Phase 3: Months 5-6 (Validation & Optimization)
- Conduct Veeam-to-Glacier backup restore simulation
- Validate firewall ACL rules with penetration testing
- Deliver staff Security Awareness Training

```

### Phase Success Metrics

* **Phase 1 Metric:** 100% of external VPN accounts converted to enforced MFA; zero consumer networking gear at branch sites.
* **Phase 2 Metric:** 100% EDR coverage on managed hosts; core servers separated into distinct VLANs with active logging in Wazuh.
* **Phase 3 Metric:** Successful recovery of test database from AWS Glacier Object Lock within 4 hours; zero unauthorized SMB traffic between clinical and database subnets.

## 9. Next Steps & Cryptographic Alignment

### Connection to Project 1x04 (Cryptographic Foundation)

With core network isolation, endpoint defenses, and quantitative risk governance established, MedDefense is prepared to transition to **Project 1x04: Cryptographic Foundation**.

While the controls funded in this strategy mitigate **availability** and **lateral movement** risks, 1x04 will address data-at-rest and data-in-transit confidentiality directly:

* **Database Encryption:** Implementing transparent data encryption (TDE) on `ehr-db-01` and billing databases to prevent data exposure from stolen raw disks or offline backups.
* **Key Management Architecture:** Replacing hardcoded passwords and unencrypted configuration files with centralized secrets management (e.g., HashiCorp Vault).
* **PKI Infrastructure:** Deploying internal Public Key Infrastructure (PKI) to enforce TLS 1.3 encryption across all internal PACS imaging traffic and medical IoT communications.

By establishing this strategy today, MedDefense ensures that upcoming cryptographic architectures operate upon a secure, well-segmented, and fully audited network foundation.
