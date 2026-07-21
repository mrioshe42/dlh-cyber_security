# 11. The Control Selection

## Control Selection & Traceability Mapping

For each mitigated risk in MedDefense's Risk Register, specific security controls are mapped to recognized frameworks (**CIS Controls** and **NIST CSF 2.0**), classified by type and category, and evaluated for cost, risk reduction, and operational dependencies.

### Individual Risk-to-Control Specifications

#### 1. RISK-001: Ransomware Campaign Encrypts EHR & Core Infrastructure

* **Risk:** `RISK-001`
* **Selected Control:** Network Segmentation (802.1Q VLANs) + MFA Deployment
* **CIS Control Mapping:** CIS Control 6.3 (Require MFA for External Network Access) & CIS Control 12.2 (Establish and Maintain Architecture Topology)
* **NIST CSF Mapping:** `PR.AC-07` (Access permissions and authorizations are managed) & `PR.DS-05` (Protections against data leaks are implemented)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $35,000 combined ($10,000 MFA + $25,000 VLANs)
* **Expected Risk Reduction:** $1,551,185 ALE Reduction
* **Dependencies:** None (Foundational baseline controls)

#### 2. RISK-002: PHI Data Exfiltration from EHR Database

* **Risk:** `RISK-002`
* **Selected Control:** Enterprise SIEM Deployment (Wazuh) & Database-at-Rest Encryption
* **CIS Control Mapping:** CIS Control 8.2 (Collect Audit Logs) & CIS Control 3.10 (Encrypt Data on End-User Devices)
* **NIST CSF Mapping:** `DE.CM-01` (Networks and environmental monitoring) & `PR.DS-01` (Data-at-rest is protected)
* **Control Type:** Detective & Preventive
* **Control Category:** Technical
* **Implementation Cost:** $36,000
* **Expected Risk Reduction:** $741,000 ALE Reduction
* **Dependencies:** Requires underlying network infrastructure and endpoint logging access.

#### 3. RISK-003: Negligent Insider Data Leakage & Credential Misuse

* **Risk:** `RISK-003`
* **Selected Control:** Endpoint Detection & Response (Sophos Intercept X) with USB Control
* **CIS Control Mapping:** CIS Control 10.3 (Deploy and Maintain Endpoint Detection and Response) & CIS Control 10.5 (Enable Anti-Exploit Features)
* **NIST CSF Mapping:** `PR.PT-01` (Audit logs are generated) & `DE.AE-03` (Event data are aggregated)
* **Control Type:** Preventive & Detective
* **Control Category:** Technical
* **Implementation Cost:** $30,000
* **Expected Risk Reduction:** $191,458 ALE Reduction
* **Dependencies:** Requires Active Directory asset discovery and endpoint agent deployment.

#### 4. RISK-004: Clinical Disruption via Medical Device Compromise

* **Risk:** `RISK-004`
* **Selected Control:** 802.1Q Medical Device VLAN Microsegmentation
* **CIS Control Mapping:** CIS Control 12.2 (Establish and Maintain Architecture Topology)
* **NIST CSF Mapping:** `PR.MA-02` (Maintenance and repair of organizational assets)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $10,000 (Allocated segment of Control 1)
* **Expected Risk Reduction:** $83,475 ALE Reduction
* **Dependencies:** **Requires completion of Control 1 (Core Network Segmentation)** to establish master switch trunking.

#### 5. RISK-005: Legacy Windows XP MRI System Exploitation

* **Risk:** `RISK-005`
* **Selected Control:** Inline Hardware Micro-Firewall (Bridge Segmentation)
* **CIS Control Mapping:** CIS Control 4.1 (Establish and Maintain a Secure Configuration Process)
* **NIST CSF Mapping:** `PR.PT-04` (Communications and control networks are protected)
* **Control Type:** Compensating / Preventive
* **Control Category:** Technical / Physical
* **Implementation Cost:** $4,000
* **Expected Risk Reduction:** $60,080 ALE Reduction
* **Dependencies:** Requires physical placement between the MRI diagnostic workstation and the core PACS network switch.

#### 6. RISK-006: Westside Clinic Perimeter Compromise

* **Risk:** `RISK-006`
* **Selected Control:** Dedicated Enterprise Firewall (FortiGate) at Branch Office
* **CIS Control Mapping:** CIS Control 4.4 (Configure automatic session locking) & CIS Control 13.1 (Centralize Security Event Alerting)
* **NIST CSF Mapping:** `PR.AC-05` (Network integrity is protected)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $4,000
* **Expected Risk Reduction:** $31,500 ALE Reduction
* **Dependencies:** None (Independent branch deployment).

#### 7. RISK-007: Lack of Centralized Threat Visibility

* **Risk:** `RISK-007`
* **Selected Control:** Enterprise SIEM Deployment (Wazuh Open-Source)
* **CIS Control Mapping:** CIS Control 8.5 (Collect Detailed Audit Logs)
* **NIST CSF Mapping:** `DE.CM-03` (Personnel activity is monitored)
* **Control Type:** Detective
* **Control Category:** Technical
* **Implementation Cost:** $36,000 (Shared with Control 3)
* **Expected Risk Reduction:** $450,000 ALE Reduction
* **Dependencies:** Requires endpoint log forwarding and network switch SNMP configurations.

#### 8. RISK-008: Ransomware Permanent Data Destruction (Missing Offsite Backups)

* **Risk:** `RISK-008`
* **Selected Control:** Offsite Immutable Cloud Backup Replication (AWS S3 Glacier Object Lock)
* **CIS Control Mapping:** CIS Control 11.4 (Establish and Maintain an Isolated Backup Capability)
* **NIST CSF Mapping:** `PR.DS-09` (Data resilience is addressed)
* **Control Type:** Corrective
* **Control Category:** Technical
* **Implementation Cost:** $15,000
* **Expected Risk Reduction:** $103,216 ALE Reduction
* **Dependencies:** Requires Veeam backup server configuration and cloud storage connector setup.

#### 9. RISK-009: Shared Administrative Credential Misuse (`raduser`)

* **Risk:** `RISK-009`
* **Selected Control:** Unique Administrative Account Provisioning & MFA
* **CIS Control Mapping:** CIS Control 5.4 (Restrict Administrator Privileges to Dedicated Account)
* **NIST CSF Mapping:** `PR.AC-01` (Identity management and access control)
* **Control Type:** Preventive
* **Control Category:** Administrative / Technical
* **Implementation Cost:** Part of Control 2 ($10,000 budget allocation)
* **Expected Risk Reduction:** $150,000 ALE Reduction
* **Dependencies:** Requires Active Directory policy restructuring.

#### 10. RISK-010: Governance Paralysis (Vacant CISO / Overlapping Authority)

* **Risk:** `RISK-010`
* **Selected Control:** Executive Governance Charter & RACI Matrix Implementation
* **CIS Control Mapping:** CIS Control 1.1 (Establish and Maintain Detailed Enterprise Asset Inventory) & Governance Frameworks
* **NIST CSF Mapping:** `GV.PO-01` (Policy is established and communicated)
* **Control Type:** Preventive
* **Control Category:** Administrative
* **Implementation Cost:** $0 (Internal administrative labor)
* **Expected Risk Reduction:** Strategic operational alignment across all risk categories.
* **Dependencies:** Requires executive board sign-off and CFO approval.


### Control Dependency Map

The following architectural flow illustrates the mandatory dependency sequence for deploying MedDefense's security controls. Certain foundational layers (such as core segmentation and identity management) must precede specialized technical implementations:

```
[Control 1: Network Segmentation (VLANs)]
       │
       ├──> Enables Downstream Isolation ──> [Control 4: Medical Device VLAN Microsegmentation]
       │
       └──> Secures Perimeter ───────────> [Control 6: Westside Clinic Firewall]

[Control 2: MFA Deployment & IAM]
       │
       └──> Enforces Account Security ───> [Control 9: Unique Admin Accounts (`raduser` elimination)]

[Control 3: Enterprise SIEM (Wazuh)] ──> Feeds Telemetry ──> [Control 5: EDR Upgrade (Intercept X)]

[Control 4: Immutable Cloud Backups] ──> Operates Independently ──> [Guarantees Data Recovery (Risk 008)]

```
