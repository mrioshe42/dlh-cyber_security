## 10: The Complete Control Matrix

### Part 1: Updated Control Registry (All Controls, All Sources)

[Registry continues from Exercise 4 with additions:]

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|-----------|--------------|----------|----------|-------------------|---------------|----|
| C-001–C-017 | [From Exercise 4] | — | — | — | — | Exercise 4 |
| C-018 | VLAN Isolation for MRI | Technical | Preventive | MRI (Windows XP), medical device network | Strong (if implemented) | Exercise 6: Compensating control design |
| C-019 | Application Whitelisting (MRI) | Technical | Preventive | MRI workstation | Strong (if configured) | Exercise 6: Compensating control design |
| C-020 | One-Way Data Flow Gateway | Technical | Preventive | PACS ↔ MRI communication | Strong (if deployed) | Exercise 6: Compensating control design |
| C-021 | Continuous Vulnerability Monitoring | Technical | Detective | MRI Windows XP, other legacy systems | Adequate | Exercise 6: Compensating control design |

### Part 2: Updated Control Summary Matrix (with counts & effectiveness)

|  | **Preventive** | **Detective** | **Corrective** | **Compensating** | **Deterrent** |
|---|---|---|---|---|---|
| **Technical** | 13 (Avg: Adequate) | 2 (Avg: Weak) | 1 (Avg: Adequate) | 3 (Avg: Strong) | — |
| **Administrative** | 1 (Adequate) | — | 3 (Avg: Weak) | — | — |
| **Physical** | 1 (Weak) | — | — | — | 1 (Weak) |

**Summary:** 21 controls identified; distribution heavily preventive (15) with critical gap in detection (2 controls cover organization-wide operations).

### Part 3: Control Coverage Map (Top 5 Critical Assets)

**Critical Asset 1: EHR System (ehr-srv-01 + ehr-db-01)**
```
Preventive: C-001 (firewall), C-004 (password policy), C-005 (AD), C-010 (DMZ for web interface if applicable)
Detective: None covering EHR specifically (SIEM missing = G-011)
Corrective: C-002 (firewall updates), C-015 (MedTech vendor support), C-016 (incident response, weak)
Compensating: None
Coverage Assessment: PARTIALLY PROTECTED
  Gap: No EDR, no SIEM, no encryption at rest, no database-level access controls, no anomaly detection
```

**Critical Asset 2: PACS/Medical Imaging**
```
Preventive: C-001 (firewall), C-011 (VPN for inter-site PACS access)
Detective: None (no image integrity monitoring, no audit of who accesses which images)
Corrective: C-015 (vendor support if available)
Compensating: None (C-020 one-way gateway not yet deployed)
Coverage Assessment: UNDER-PROTECTED
  Gap: Shared login prevents accountability; no VLAN segmentation; no encryption; no access audit
```

**Critical Asset 3: Medical IoT (Infusion Pumps, Vital Monitors)**
```
Preventive: C-001 (perimeter firewall only; no device segmentation), C-003 (endpoint antivirus does not cover medical devices)
Detective: None (no device monitoring, no anomaly detection on pump commands or vital signs)
Corrective: None
Compensating: C-018 (VLAN for MRI, can be applied to all IoT)
Coverage Assessment: UNPROTECTED
  Gap: Completely absent of detective controls for life-safety-critical devices; no network segmentation for IoT; no integrity checking of firmware/dosages
```

**Critical Asset 4: Network Core (Cisco switches, FortiGate)**
```
Preventive: C-001 (self-protecting firewall), no controls on switch configuration (unmanaged switch at Westside = C-016 weak)
Detective: None (no netflow monitoring, no IDS/IPS, no switch config audit)
Corrective: C-002 (Fortinet support for patches)
Compensating: None
Coverage Assessment: PARTIALLY PROTECTED
  Gap: No detection of lateral movement (flat network enables lateral movement undetected); no switch configuration monitoring; consumer router at Westside (C-017) is unprotected
```

**Critical Asset 5: Billing System (billing-srv-01)**
```
Preventive: C-001 (firewall), C-003 (Sophos antivirus, weak), C-004 (password policy), C-005 (AD)
Detective: None (crypto-miner on this system for unknown duration = undetected, Exercise 2)
Corrective: C-002 (firewall updates), C-017 (backup for recovery, weak due to co-location)
Compensating: None specific to financial data
Coverage Assessment: UNDER-PROTECTED
  Gap: No EDR/behavior monitoring (ransomware, crypto-miner missed); no database encryption; no data exfiltration detection; no payment card-specific controls documented (PCI-DSS compliance unclear)
```
