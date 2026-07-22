# 8. The Budget Game

Making binding capital allocation decisions under a strict **$120,000 annual budget** requires prioritizing maximum financial return while accepting calculated residual risks. Every dollar spent must be tied directly to quantitative risk reduction.

## Part 1: Capital Allocation & Control Selection

### Budget Usage Summary
* **Total Budget Ceiling:** $120,000
* **Total Spend:** $120,000
* **Remaining Budget:** $0

### Funded Controls ($120,000 Total Allocation)

The following combination of funded controls was selected to maximize total risk reduction within the strict $120,000 budget constraint. Selection is based purely on net value and risk reduction efficiency rather than arbitrary preference.

* **Control 2: MFA Deployment on VPN and Administrative Accounts**
  * **Allocated Cost:** **$10,000** ($0 software license via M365 E3 + $10,000 labor)
  * **Role:** Primary initial access defense. Eliminates 90% of credential-based entry vectors.
  * **Selection Reasoning:** Funded due to extreme risk reduction efficiency ($2,041,875 ALE reduction for $10,000 cost).

* **Control 1: Network Segmentation (802.1Q VLANs)**
  * **Allocated Cost:** **$25,000** ($15,000 implementation labor + $10,000 hardware)
  * **Role:** Containment architecture. Breaks up the flat `10.10.0.0/16` network to halt lateral movement across servers, workstations, and medical subnets.
  * **Selection Reasoning:** Funded as the fundamental dependency for containment and medical device protection ($1,551,185 ALE reduction).

* **Control 3: Enterprise SIEM Deployment (Wazuh Open-Source)**
  * **Allocated Cost:** **$36,000** ($0 license + $30,000 labor/tuning + $6,000 cloud storage)
  * **Role:** Centralized log monitoring and threat detection across all 540 endpoints and core databases.
  * **Selection Reasoning:** Funded to establish real-time visibility and detect active threats across all systems ($741,000 ALE reduction).

* **Control 5: Endpoint Detection and Response Upgrade (Sophos Intercept X)**
  * **Allocated Cost:** **$30,000** ($24,300 licensing + $5,700 deployment labor)
  * **Role:** Behavioral anti-ransomware protection and USB device control across all endpoints.
  * **Selection Reasoning:** Funded to provide active behavioral protection against zero-day ransomware ($191,458 ALE reduction).

* **Control 4: Offsite Immutable Backup Replication (AWS S3 Glacier)**
  * **Allocated Cost:** **$15,000** ($10,000 storage + $5,000 Veeam cloud connector)
  * **Role:** Guarantees ransomware recovery without paying extortion fees by enforcing 3-2-1 immutable backups.
  * **Selection Reasoning:** Funded to ensure business continuity and recovery resilience ($103,216 ALE reduction).

* **Control 6: Dedicated Firewall for Westside Clinic**
  * **Allocated Cost:** **$4,000** ($1,200 hardware + $800 UTM sub + $2,000 labor)
  * **Role:** Perimeter hardening at the remote branch to prevent site-to-site VPN pivoting.
  * **Selection Reasoning:** Funded to eliminate critical remote branch vulnerability at low cost ($31,500 ALE reduction).

### Deferred Controls (Pushed to FY27 Planning)

* **Control 8: Full Medical Device Isolation with Dedicated Monitoring (Medical NAC Platform)**
  * **Allocated Cost:** **$0 (Deferred)**
  * **Reasoning:** At $90,000/year, funding this control under the current $120,000 budget would force the de-funding of core controls like EDR and SIEM, destroying overall portfolio risk reduction. Deferring this control allows MedDefense to re-negotiate vendor pricing in FY27 while relying on general VLAN microsegmentation (Control 1) as a low-cost compensating control in the interim.

### Rejected Controls

* **Control 7: 24/7 Security Operations Center Staffing (Outsourced MSSP)**
  * **Allocated Cost:** **$0 (Rejected)**
  * **Reasoning:** At $180,000/year, this service exceeds the entire annual security budget by 150% and delivers negative net value (-$60,000). It is rejected for defensible financial reasons: threat monitoring is handled far more cost-effectively via internal Wazuh SIEM (Control 3) and Sophos Intercept X EDR (Control 5) at a fraction of the cost.

## Part 2: Opportunity Cost Analysis

De-prioritizing controls leaves specific residual annual risk exposure on the balance sheet. Quantifying these unmitigated risks ensures leadership explicitly understands the trade-offs accepted by the business:

> **Formal Opportunity Cost Statements:**
> * "By deferring **Control 8 (Full Medical Device Isolation with Dedicated Monitoring)**, MedDefense accepts an estimated **$9,275** in annual risk exposure across unmonitored medical IoT devices that is not fully contained by general VLAN segmentation."
> * "By rejecting **Control 7 (24/7 Managed SOC Staffing)**, MedDefense accepts an estimated **$120,000** in annual risk exposure associated with off-hours security alert response delays."

## Part 3: Alternative Allocation Strategy

To evaluate financial resilience, an **Alternative Allocation Strategy (Plan B)** is proposed. Plan B defers the EDR upgrade to establish a **25% budget reserve ($30,000)** for scope creep, emergency incident response retainers, or unplanned hardware requirements.

### Alternative Allocation Plan B ($90,000 Spend / $30,000 Reserve)

| Control | Status | Annual Cost | ALE Reduction | Net Value |
| :--- | :--- | :--- | :--- | :--- |
| **Control 2: MFA Deployment** | Funded | $10,000 | $2,041,875 | $2,031,875 |
| **Control 1: Network Segmentation** | Funded | $25,000 | $1,551,185 | $1,526,185 |
| **Control 3: Enterprise SIEM (Wazuh)** | Funded | $36,000 | $741,000 | $705,000 |
| **Control 4: Offsite Immutable Backups** | Funded | $15,000 | $103,216 | $88,216 |
| **Control 6: Westside Clinic Firewall** | Funded | $4,000 | $31,500 | $27,500 |
| **Control 5: EDR Upgrade** | **Deferred to FY27** | $0 | $0 | $0 |
| **Total Allocation / Risk Reduction** | | **$90,000** | **$4,467,776** | **$4,377,776** |

### Plan Comparison: Primary vs. Alternative

| Decision Metric | Primary Plan (Full $120k Allocation) | Alternative Plan B ($90k Prudent Allocation) |
| :--- | :--- | :--- |
| **Annual Capital Spend** | $120,000 | $90,000 |
| **Remaining Budget Reserve** | **$0** | **$30,000** |
| **Gross Annual ALE Reduction** | **$4,659,234** | $4,467,776 |
| **Net Financial Return Delivered** | **$4,539,234** | $4,377,776 |
| **Risk Reduction Efficiency** | **100.0%** | **95.9%** |

### Comparison Analysis & Strategic Trade-offs

* **Primary Plan ($120,000 Spend):** Maximizes absolute risk reduction ($4,659,234 eliminated) by closing all primary endpoints, network, and backup gaps, but leaves **$0 in remaining budget reserves**.
* **Alternative Plan B ($90,000 Spend):** Captures **95.9% of achievable risk reduction** ($4,467,776) while creating a **$30,000 cash buffer**. The trade-off is accepting **$191,458 in unmitigated EDR risk**, which is temporarily absorbed by existing basic antivirus and network VLAN segmentation until FY27. While Plan B increases operational liquidity, the Primary Plan is recommended because EDR behavioral protection is crucial for stopping modern zero-day ransomware attacks before encryption occurs.
