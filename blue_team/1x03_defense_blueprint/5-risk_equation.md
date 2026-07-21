# 5. The Risk Equation

## Quantitative Risk Analysis

This quantitative risk analysis evaluates five core risk scenarios for MedDefense Health Systems using standard single loss and annualized expectancy formulas:

$$\text{Single Loss Expectancy (SLE)} = \text{Asset Value (AV)} \times \text{Exposure Factor (EF)}$$

$$\text{Annualized Loss Expectancy (ALE)} = \text{Single Loss Expectancy (SLE)} \times \text{Annualized Rate of Occurrence (ARO)}$$

### Scenario 1: Ransomware Attack on Billing Server (`billing-srv-01`)

#### 1. Asset Value (AV) Reasoning

The value of `billing-srv-01` is defined by the revenue stream and operational liability it supports, rather than the physical hardware cost.

* **18-Day Revenue Loss:** $18 \text{ days} \times \$16,000/\text{day} = \$288,000$
* **Forensic & Recovery Costs:** $\$85,000$
* **HIPAA Regulatory Fine:** $\$100,000$ (mid-range assumption for financial/PHI compromise)
* **Total Asset Exposure Value ($AV$):** $\$473,000$

#### 2. Exposure Factor (EF) Reasoning

During a ransomware encryption event, the server is rendered $100\%$ unusable for billing operations until remediated, and all associated recovery costs and penalties are triggered.

* **Exposure Factor ($EF$):** $1.0$ ($100\%$)

#### 3. Single Loss Expectancy (SLE)

$$SLE = AV \times EF = \$473,000 \times 1.0 = \$473,000$$

#### 4. Annualized Rate of Occurrence (ARO) Reasoning

Industry intelligence indicates a ransomware attack occurs once every $3.5$ years for a hospital of MedDefense's profile without EDR or network microsegmentation.

* **Annualized Rate of Occurrence ($ARO$):** $\frac{1}{3.5} \approx 0.286$ attacks/year

#### 5. Annualized Loss Expectancy (ALE)

$$ALE = SLE \times ARO = \$473,000 \times 0.286 = \$135,278 / \text{year}$$

#### 6. Confidence Level & Key Sensitivity

* **Confidence Level:** **Medium**
* **Sensitivity Factor:** **Downtime Duration.** If MedDefense maintains immutable backups and reduces downtime from $18$ days to $3$ days, the lost revenue drops from $\$288,000$ to $\$48,000$, lowering $SLE$ to $\$233,000$ and cutting the annual loss ($ALE$) down to $\$66,638$.

### Scenario 2: Patient Data Breach via EHR System (`ehr-srv-01` / `ehr-db-01`)

#### 1. Asset Value (AV) Reasoning

The asset value reflects the total liability of compromising all $50,000$ Electronic Health Records stored in the database.

* **Per-Record Breach Liability:** $50,000 \text{ records} \times \$165/\text{record} = \$8,250,000$
* **Breach Notification Infrastructure:** $\$25,000$
* **Class-Action Litigation Exposure:** $\$200,000$
* **Reputational Loss (Patient Attrition):** $\$600,000$
* **Total Asset Exposure Value ($AV$):** $\$9,075,000$

#### 2. Exposure Factor (EF) Reasoning

A full database exfiltration event exposes $100\%$ of the stored patient records, triggering notification requirements, legal action, and reputational attrition across the entire patient base.

* **Exposure Factor ($EF$):** $1.0$ ($100\%$)

#### 3. Single Loss Expectancy (SLE)

$$SLE = AV \times EF = \$9,075,000 \times 1.0 = \$9,075,000$$

#### 4. Annualized Rate of Occurrence (ARO) Reasoning

Given an unencrypted flat network, unpatched vulnerabilities, and missing database access controls, the likelihood of an exfiltration event is estimated at once every $3$ years.

* **Annualized Rate of Occurrence ($ARO$):** $\frac{1}{3} \approx 0.333$ breaches/year

#### 5. Annualized Loss Expectancy (ALE)

$$ALE = SLE \times ARO = \$9,075,000 \times 0.333 = \$3,021,975 / \text{year}$$

#### 6. Confidence Level & Key Sensitivity

* **Confidence Level:** **Medium**
* **Sensitivity Factor:** **Exfiltration Volume.** The calculation assumes an attacker exfiltrates the entire database ($50,000$ records). If an attacker exfiltrates only a subset of $5,000$ records ($10\%$), the direct record cost drops from $\$8,250,000$ to $\$825,000$, reducing $SLE$ to $\$1,650,000$ and the $ALE$ to $\$549,450$.

### Scenario 3: Negligent Insider Data Theft

#### 1. Asset Value (AV) Reasoning

Across $280$ clinical workstations with $2,000$ staff members, the cost per negligent insider incident (credential leaks, unauthorized USB transfer, policy non-compliance) encompasses:

* **Investigation:** $\$30,000$
* **Containment:** $\$25,000$
* **Remediation:** $\$40,000$
* **Regulatory Reporting:** $\$25,000$
* **Total Cost per Incident ($AV$):** $\$120,000$

#### 2. Exposure Factor (EF) Reasoning

Each individual negligent incident incurs the complete procedural and regulatory cost required to investigate and contain the event.

* **Exposure Factor ($EF$):** $1.0$ ($100\%$)

#### 3. Single Loss Expectancy (SLE)

$$SLE = AV \times EF = \$120,000 \times 1.0 = \$120,000$$

#### 4. Annualized Rate of Occurrence (ARO) Reasoning

Healthcare benchmarks show negligent insiders drive $60\%$ of insider incidents. Due to the lack of Data Loss Prevention (DLP), active USB ports, shared credentials (`raduser`), and absent security awareness training, MedDefense experiences an estimated $2.5$ incidents per year.

* **Annualized Rate of Occurrence ($ARO$):** $2.5$ incidents/year

#### 5. Annualized Loss Expectancy (ALE)

$$ALE = SLE \times ARO = \$120,000 \times 2.5 = \$300,000 / \text{year}$$

#### 6. Confidence Level & Key Sensitivity

* **Confidence Level:** **High**
* **Sensitivity Factor:** **Incident Frequency ($ARO$).** Implementing basic DLP controls, disabling USB ports, and conducting mandatory employee training could reduce the incident rate from $2.5$ to $0.5$ per year, cutting $ALE$ by $\$240,000$ annually.

### Scenario 4: BD Alaris Infusion Pump Compromise

This scenario evaluates two distinct outcome vectors: a Denial-of-Service (DoS) disruption versus a Patient Safety dosing incident.

#### Part A: Denial-of-Service (DoS) / Operational Disruption

1. **Asset Value ($AV$):** $\$120,000$ (5 days operational disruption at $\$20,000/\text{day} = \$100,000$, plus $\$20,000$ vendor re-imaging).
2. **Exposure Factor ($EF$):** $1.0$ ($100\%$)
3. **Single Loss Expectancy ($SLE_{\text{DoS}}$):** $\$120,000 \times 1.0 = \$120,000$
4. **Annualized Rate of Occurrence ($ARO_{\text{DoS}}$):** $0.10$ ($1\text{ in } 10\text{ years}$)
5. **Annualized Loss Expectancy ($ALE_{\text{DoS}}$):** $\$120,000 \times 0.10 = \$12,000 / \text{year}$

#### Part B: Patient Safety Incident (Dosing Manipulation)

1. **Asset Value ($AV$):** $\$2,750,000$ (Malpractice liability settlement: $\$2,500,000$; FDA investigation: $\$150,000$; Quarantine operational impact: $\$100,000$).
2. **Exposure Factor ($EF$):** $1.0$ ($100\%$)
3. **Single Loss Expectancy ($SLE_{\text{Safety}}$):** $\$2,750,000 \times 1.0 = \$2,750,000$
4. **Annualized Rate of Occurrence ($ARO_{\text{Safety}}$):** $0.02$ ($1\text{ in } 50\text{ years}$)
5. **Annualized Loss Expectancy ($ALE_{\text{Safety}}$):** $\$2,750,000 \times 0.02 = \$55,000 / \text{year}$

#### Combined Medical Device Risk

$$ALE_{\text{Total}} = ALE_{\text{DoS}} + ALE_{\text{Safety}} = \$12,000 + \$55,000 = \$67,000 / \text{year}$$

#### Confidence Level & Key Sensitivity

* **Confidence Level:** **Low**
* **Sensitivity Factor:** **Legal Settlement Severity ($SLE$).** Malpractice damages from a fatal dosing error can vary between $\$500,000$ and $\$5,000,000+$. A higher jury award significantly elevates $SLE$ and $ALE$.

### Scenario 5: FortiGate VPN Compromise (Full Network Entry)

#### 1. Asset Value (AV) Reasoning

Compromising the central FortiGate VPN grants direct entry into the flat `10.10.0.0/16` internal subnet. An attacker can execute a dual-threat campaign (data exfiltration plus mass ransomware encryption across Active Directory, EHR, and backup repositories).

* **Data Breach Liabilities (Scenario 2):** $\$9,075,000$
* **Billing System Ransomware & Downtime (Scenario 1):** $\$473,000$
* **Domain Rebuild & Hospital-Wide System Recovery:** $\$500,000$
* **Total Aggregate Asset Exposure ($AV$):** $\$10,048,000$

#### 2. Exposure Factor (EF) Reasoning

Because the network lacks internal VLAN segmentation, an unauthenticated entry at the VPN perimeter grants unrestricted access to all connected internal assets.

* **Exposure Factor ($EF$):** $1.0$ ($100\%$)

#### 3. Single Loss Expectancy (SLE)

$$SLE = AV \times EF = \$10,048,000 \times 1.0 = \$10,048,000$$

#### 4. Annualized Rate of Occurrence (ARO) Reasoning

Edge VPN devices are the primary initial access vector in $38\%$ of healthcare ransomware attacks. Unpatched edge hardware without enforced Multi-Factor Authentication carries a high likelihood of compromise.

* **Annualized Rate of Occurrence ($ARO$):** $0.30$ ($1\text{ every } 3.3\text{ years}$)

#### 5. Annualized Loss Expectancy (ALE)

$$ALE = SLE \times ARO = \$10,048,000 \times 0.30 = \$3,014,400 / \text{year}$$

#### 6. Confidence Level & Key Sensitivity

* **Confidence Level:** **Medium-Low**
* **Sensitivity Factor:** **Lack of Network Segmentation ($EF$).** If MedDefense deploys 802.1Q VLAN microsegmentation, a VPN breach remains contained within the DMZ or initial landing segment, preventing lateral movement to the EHR database or backup targets. This reduces $EF$ from $1.0$ to $0.10$, dropping $SLE$ to $\$1,004,800$ and $ALE$ to $\$301,440$.

### Quantitative Risk Summary

| Scenario | Asset Value ($AV$) | Exposure Factor ($EF$) | Single Loss Expectancy ($SLE$) | Annualized Rate of Occurrence ($ARO$) | Annualized Loss Expectancy ($ALE$) | Confidence Level |
| --- | --- | --- | --- | --- | --- | --- |
| **1. Billing Server Ransomware** | $\$473,000$ | $1.0$ | $\$473,000$ | $0.286$ | **$\$135,278$** | Medium |
| **2. Patient EHR Data Breach** | $\$9,075,000$ | $1.0$ | $\$9,075,000$ | $0.333$ | **$\$3,021,975$** | Medium |
| **3. Negligent Insider Data Theft** | $\$120,000$ | $1.0$ | $\$120,000$ | $2.500$ | **$\$300,000$** | High |
| **4. Medical Device Compromise** | $\$2,870,000$ | $1.0$ | $\$2,870,000$ | Combined | **$\$67,000$** | Low |
| **5. VPN Perimeter Compromise** | $\$10,048,000$ | $1.0$ | $\$10,048,000$ | $0.300$ | **$\$3,014,400$** | Medium-Low |
