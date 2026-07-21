# 7. The Cost-Benefit Analysis

Evaluating security controls against Annualized Loss Expectancy ($\text{ALE}$) demonstrates return on investment to executive leadership. A control is financially justified when:

$$\text{ALE}_{\text{Reduction}} (\text{ALE}_{\text{Before}} - \text{ALE}_{\text{After}}) > \text{Annual Control Cost}$$

If the control costs more than the risk reduction it provides, the rational financial decision is to accept the risk or select a lower-cost compensating control.

### Control Evaluations

#### Control 1: Network Segmentation (VLAN Implementation)

* **CIS Control Reference:** CIS Control 12 (Network Infrastructure Management)
* **Annual Cost:** **$25,000** ($0 license + $15,000 professional implementation labor + $10,000 managed switch hardware & maintenance)
* **Risk(s) Addressed:** Risk 1 (Ransomware EHR Encryption), Risk 4 (Medical Device Disruption), Risk 5 (Legacy MRI System Exploitation)
* **ALE Reduction:** **$1,551,185** ($1,731,450 baseline combined ALE - $180,265 residual combined ALE by containing lateral movement across subnets)
* **Net Value:** $\$1,551,185 - \$25,000 = \mathbf{\$1,526,185}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** immediately to isolate core servers, clinical workstations, and medical device subnets to halt lateral ransomware propagation.

#### Control 2: MFA Deployment on VPN and Administrative Accounts

* **CIS Control Reference:** CIS Control 6 (Access Control Management)
* **Annual Cost:** **$10,000** ($0 new software licensing using existing Microsoft 365 E3 features + $10,000 configuration, rollout, and onboarding labor)
* **Risk(s) Addressed:** Risk 1 (Ransomware EHR Encryption), Risk 2 (PHI Data Exfiltration)
* **ALE Reduction:** **$2,041,875** ($2,268,750 baseline combined ALE - $226,875 residual combined ALE by eliminating 90% of credential compromise entry vectors)
* **Net Value:** $\$2,041,875 - \$10,000 = \mathbf{\$2,031,875}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** immediately as an ultra-high-return quick win leveraging existing software entitlements.

#### Control 3: Enterprise SIEM Deployment (Wazuh, Open-Source)

* **CIS Control Reference:** CIS Control 8 (Audit Log Management)
* **Annual Cost:** **$36,000** ($0 open-source software license + $30,000 deployment and log parsing labor + $6,000 cloud log storage)
* **Risk(s) Addressed:** Risk 2 (PHI Data Exfiltration), Risk 3 (Negligent Insider Data Leakage)
* **ALE Reduction:** **$741,000** ($1,001,250 baseline combined ALE - $260,250 residual combined ALE by enabling rapid detection of exfiltration and unauthorized queries)
* **Net Value:** $\$741,000 - \$36,000 = \mathbf{\$705,000}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** to establish central logging and breach detection capabilities across all servers without ongoing commercial licensing fees.

#### Control 4: Offsite Backup Replication (AWS S3 Glacier Immutable Storage)

* **CIS Control Reference:** CIS Control 11 (Data Recovery)
* **Annual Cost:** **$15,000** ($10,000 AWS S3 Glacier Object Lock storage for 50TB + $5,000 Veeam cloud connector licenses and maintenance)
* **Risk(s) Addressed:** Risk 1 (Ransomware EHR Encryption)
* **ALE Reduction:** **$103,216** ($1,567,500 baseline ALE - $1,464,284 residual ALE by reducing recovery times from 14 days to 2 days and eliminating ransom payments)
* **Net Value:** $\$103,216 - \$15,000 = \mathbf{\$88,216}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** to enforce immutable 3-2-1 backup architecture and guarantee clean operational restore points during a ransomware event.

#### Control 5: Endpoint Detection and Response Upgrade (Sophos Intercept X)

* **CIS Control Reference:** CIS Control 10 (Malware Defenses)
* **Annual Cost:** **$30,000** ($24,300 license upgrade for 540 endpoints @ $45/host/year + $5,700 policy tuning and deployment labor)
* **Risk(s) Addressed:** Risk 1 (Ransomware EHR Encryption), Risk 3 (Negligent Insider Data Leakage)
* **ALE Reduction:** **$191,458** ($1,867,500 baseline combined ALE - $1,676,042 residual combined ALE by blocking exploit payloads and unauthorized USB storage)
* **Net Value:** $\$191,458 - \$30,000 = \mathbf{\$161,458}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** by upgrading existing Sophos instances to Intercept X to provide behavioral anti-ransomware and device control.

#### Control 6: Dedicated Firewall for Westside Clinic

* **CIS Control Reference:** CIS Control 4 (Secure Configuration of Enterprise Assets and Software)
* **Annual Cost:** **$4,000** ($1,200 FortiGate appliance + $800 annual UTM subscription + $2,000 installation labor)
* **Risk(s) Addressed:** Branch site perimeter breach and VPN pivoting into the central network (Risk 1 & Risk 2 vectors)
* **ALE Reduction:** **$31,500** ($35,000 baseline branch exposure - $3,500 residual exposure)
* **Net Value:** $\$31,500 - \$4,000 = \mathbf{\$27,500}$
* **Verdict:** **Justified**
* **Recommendation:** **Implement** immediately to replace the unmanaged consumer router at Westside Clinic with an enterprise-grade perimeter firewall.

#### Control 7: 24/7 Security Operations Center Staffing (Outsourced MSSP)

* **CIS Control Reference:** CIS Control 13 (Network Monitoring and Defense)
* **Annual Cost:** **$180,000** ($15,000/month MSSP retainer fee for 540 endpoints)
* **Risk(s) Addressed:** Risk 1 (Ransomware EHR Encryption), Risk 2 (PHI Data Exfiltration)
* **ALE Reduction:** **$120,000** (Provides marginal off-hours detection beyond internal SIEM and EDR capabilities)
* **Net Value:** $\$120,000 - \$180,000 = \mathbf{-\$60,000}$
* **Verdict:** **Not Justified**
* **Recommendation:** **Reject** because the annual operational cost exceeds the financial risk reduction achieved beyond internal Wazuh SIEM and Sophos EDR controls.

#### Control 8: Full Medical Device Isolation with Dedicated Monitoring (Medical NAC Platform)

* **CIS Control Reference:** CIS Control 12 & CIS Control 13
* **Annual Cost:** **$90,000** ($70,000 specialized medical NAC software subscription + $20,000 hardware appliance and consulting)
* **Risk(s) Addressed:** Risk 4 (Medical Device Disruption)
* **ALE Reduction:** **$83,475** ($92,750 baseline ALE - $9,275 residual ALE)
* **Net Value:** $\$83,475 - \$90,000 = \mathbf{-\$6,525}$
* **Verdict:** **Not Justified**
* **Recommendation:** **Reject** because the subscription cost exceeds the total financial risk exposure of the medical devices, which basic network segmentation already mitigates.

### Cost-Benefit Summary Table

Controls are ranked by **Net Value** (highest return on investment first):

| Rank | Proposed Control | CIS Ref | Annual Cost | ALE Reduction | Net Value | Verdict | $120k Budget Allocation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **1** | **Control 2: MFA Deployment** | CIS 6 | $10,000 | $2,041,875 | **$2,031,875** | Justified | **Funded** ($10,000) |
| **2** | **Control 1: Network Segmentation** | CIS 12 | $25,000 | $1,551,185 | **$1,526,185** | Justified | **Funded** ($35,000) |
| **3** | **Control 3: Enterprise SIEM (Wazuh)** | CIS 8 | $36,000 | $741,000 | **$705,000** | Justified | **Funded** ($71,000) |
| **4** | **Control 5: EDR Upgrade (Intercept X)** | CIS 10 | $30,000 | $191,458 | **$161,458** | Justified | **Funded** ($101,000) |
| **5** | **Control 4: Offsite Backups (Glacier)** | CIS 11 | $15,000 | $103,216 | **$88,216** | Justified | **Funded** ($116,000) |
| **6** | **Control 6: Westside Clinic Firewall** | CIS 4 | $4,000 | $31,500 | **$27,500** | Justified | **Funded** ($120,000) |
| **7** | **Control 8: Dedicated Medical NAC** | CIS 12/13 | $90,000 | $83,475 | **-$6,525** | Not Justified | Excluded |
| **8** | **Control 7: 24/7 Managed SOC** | CIS 13 | $180,000 | $120,000 | **-$60,000** | Not Justified | Excluded |

> **Budget Allocation Result:** Funding Controls 1 through 6 consumes **exactly $120,000** of the annual budget while eliminating **$4,659,234 in annual risk exposure**, delivering **$4,539,234 in net financial value** to MedDefense Health Systems.
