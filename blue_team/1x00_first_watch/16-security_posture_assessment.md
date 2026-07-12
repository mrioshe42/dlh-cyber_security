## 16: The Security Posture Assessment

### MedDefense Health Systems Security Posture Assessment

#### Executive Summary

**Current Security Posture:** MedDefense Health Systems operates with adequate perimeter controls (firewall, VPN) but critical gaps in threat detection, incident response capability, and operational resilience. The organization has experienced three significant security incidents in six months (January ransomware, February data breach, June crypto-miner) without formal incident response procedures or detection mechanisms, indicating that current controls are insufficient for the healthcare threat landscape.

**Single Most Critical Finding:** The organization has no centralized threat detection (SIEM, IDS, or security monitoring). This means attackers can establish persistence, exfiltrate data or deploy ransomware without any organizational awareness until clinical impact becomes visible or patients report incidents. The January ransomware took 4 days to discover and respond. The June crypto-miner was undetected for an unknown duration. The February portal breach was discovered when a patient reported seeing another patient's lab results.

**Top 3 Recommended Actions:**
1. **Deploy SIEM and Endpoint Detection (EDR)** — establishes real-time threat detection across network and endpoints; required for effective incident response; estimated cost $80K Year 1, $60K ongoing.
2. **Develop and test Incident Response Plan** — formalizes response procedures and roles; enables breach containment within hours instead of days; estimated cost $15K.
3. **Implement network segmentation for medical IoT** — isolates life-safety-critical devices (infusion pumps, vital monitors) from general workstations; prevents unauthorized modification of dosages; estimated cost $10K.

**Budget Implication:** Recommended Year 1 security investment is $120K (SIEM, EDR, IR plan, network segmentation, interim physical access controls). This is a one-time investment that significantly reduces breach likelihood and response time, with annual ongoing costs of ~$60–80K for SIEM/EDR licensing and SOC staffing.

#### Scope and Methodology

**Assessed:**
- Three MedDefense sites: Central Hospital (350-bed acute care, 1,400 staff), Westside Clinic (outpatient, 180 staff), Corporate HQ (administrative, 220 staff)
- 21 servers, 500+ endpoints, 10+ network devices, 200+ medical IoT devices
- All data categories: patient records (EHR, PACS), financial data (billing), employee records (HR), credentials (AD)

**Information Sources:**
- Onboarding packet (HR guide, IT asset list, network diagram, org chart, IT contracts)
- Marcus Webb's security notes and incident observations
- Physical walk-through observations of Central facility
- Network scan summary and system diagnostics
- Healthcare breach case studies
- Incident log analysis (6 months of security events)

**Limitations:**
- Onboarding packet is incomplete (many systems marked [UNVERIFIED], asset counts 8 months old)
- Network scan was not provided in full detail; asset inventory is best-estimate
- No vulnerability assessment was conducted (time constraint); posture assessment is based on configuration review, not exploitation testing
- No interviews with clinical staff regarding workflow security; recommendations assume current workflows are maintained

#### Asset Landscape

**Asset Inventory (Summarized):**
- Servers: 9 at Central (EHR, billing, imaging, infrastructure), 1 at Westside, 0 on-premise at HQ
- Network devices: Cisco switches (model unknown), Fortinet firewall, Westside consumer router (Netgear)
- Endpoints: ~500 workstations and laptops across all sites
- Medical IoT: ~80 vital monitors, ~120 infusion pumps, 2 imaging scanners (MRI Windows XP, CT unknown OS)
- Data stores: EHR database (50,000 patient records), PACS archive (hundreds of thousands of images), billing database, file shares

**Top 5 Critical Assets:** (See Exercise 8)

#### Current Security Controls

**Control Summary:**
- 21 controls identified across Technical (13), Administrative (4), Physical (2) categories
- Distribution: Preventive (15), Detective (2), Corrective (4)
- Effectiveness: 3 Strong, 9 Adequate, 5 Weak

**Key Strengths:**
- Perimeter firewall (FortiGate) provides internet-facing protection
- Active Directory centralized authentication
- O365 provides email and collaboration with encryption in transit
- Backup software (Veeam) enables data recovery capability

**Key Weaknesses:**
- No network monitoring (SIEM, IDS) = zero visibility into internal network traffic or lateral movement
- No endpoint detection (EDR) = reliance solely on antivirus signatures (crypto-miner bypassed this)
- No database encryption at rest = stolen backups or breached servers expose plaintext patient data
- No physical access audit trail = cannot determine who accessed server room after-hours
- No incident response plan = ad-hoc response to incidents (January incident took 4 days)

#### Gap Analysis

**Top 10 Critical / High Priority Gaps:** (See Exercise 12)

**Gap Distribution:**
- 5 Critical gaps: Medical IoT segmentation, network detection, physical audit, incident response, business continuity
- 6 High gaps: Encryption at rest, Westside network, endpoint detection, encryption in transit, endpoint coverage

**Most Exposed Asset Categories:**
- Network infrastructure (3 gaps): No segmentation, no detection, unmanaged Westside equipment
- Clinical systems (4 gaps): IoT vulnerability, no BCP, Windows XP, Westside isolation

#### Risk Treatment Recommendations

**Year 1 Priorities (Total: $120K budget):**

| Rank | Gap | Treatment | Cost | Timeline | Impact |
|------|-----|-----------|------|----------|--------|
| 1 | No SIEM | Deploy SIEM + configure log collection | $60K | 6–8 weeks | Detects attacker persistence, lateral movement, data exfiltration within 24 hours |
| 2 | Weak endpoints | Deploy EDR on all 500+ endpoints | $30K | 4–6 weeks | Detects malware/ransomware/lateral movement before encryption/exfiltration |
| 3 | No IR plan | Develop formal incident response procedures | $10K | 3–4 weeks | Enables 4-hour incident containment (vs. 4-day ad-hoc response) |
| 4 | Medical IoT unprotected | VLAN segmentation for infusion pumps/monitors | $10K | 2–3 weeks | Prevents unauthorized dosage/vital modification; isolates life-safety devices |
| 5 | Physical access unmonitored | Door lock + manual access log | $10K | 1–2 weeks | Interim until Badge + camera system funded; deters opportunistic server room breach |

**Year 2 Roadmap:**
- Database encryption: $15K (protect data if backup stolen)
- Business continuity plan: $30K (enable recovery from ransomware/outage within RTO)
- Physical access system: $20K (badge reader + camera monitoring)
- Westside network upgrade: $20K (firewall, managed switch, network monitoring)

#### Conclusion and Next Steps

**Business Context:**
MedDefense operates a 350-bed acute care hospital with 50,000+ active patients, processing $100M+ in annual billing, with life-safety-critical infrastructure (infusion pumps, vital monitors). Security breaches directly threaten patient safety (incorrect medication), operational continuity (ransomware, power loss), and organizational solvency (breach costs, regulatory fines, reputational damage).

**Current Risk Level:** HIGH. The organization is experiencing active exploitation (proven by three incidents in six months) with no detection or incident response capability. Each incident is handled reactively. No systematic learning or control improvement occurs between incidents.

**If Recommendations Are Not Implemented:**
Within 12 months, a ransomware incident will likely encrypt all systems (EHR, billing, imaging, backups simultaneously); organization will face 7–10 day outage, $2M+ in direct costs (ransom, recovery, revenue loss), regulatory penalties (CMS can decertify providers for security failures), litigation (breach notification to 50K patients, identity theft lawsuits), and reputational damage potentially triggering competitive hospital market shift.

**Next Phase:** Threat Landscape Assessment
After implementing detection controls (SIEM, EDR), conduct formal threat landscape analysis to identify which threat actors specifically target healthcare organizations like MedDefense, their known tactics/techniques/procedures (TTPs), and how MedDefense's architecture enables specific attack paths. This will refine Year 2 priorities and establish a strategic threat-informed approach to security investment.
