# 16. The Risk Appetite Debate

## Governance & Risk Management: Risk Appetite Framework

### Part 1: Risk Appetite Statement

MedDefense operates with a **Moderate Risk Appetite** regarding operational and administrative systems, acknowledging that security investments must balance financial stewardship with operational continuity. However, MedDefense maintains a **Zero-Tolerance Policy (Zero Appetite)** for risks that directly impact patient safety, life support infrastructure, or cause systemic breach of regulatory PHI confidentiality. Any security risk with an estimated Single Loss Expectancy ($\text{SLE}$) exceeding **$100,000** or posing a threat to human life cannot be accepted by IT staff; such risks require formal review and explicit written sign-off from the **Board of Directors and Chief Executive Officer (CEO)**.

### Part 2: The Three Risk Acceptance Decisions

#### 1. Legacy Windows XP Workstation on MRI System

* **Risk ID:** `RISK-05` (Legacy System Vulnerability / Lateral Movement)
* **Treatment Decision:** **Accept** (Temporary Risk Acceptance)
* **Authority:** **Chief Operating Officer (COO) & Board Audit Committee**
* *Why:* Replacing the underlying $2.1M MRI scanner prior to lease expiration would cause severe capital disruption, directly impacting operational patient throughput and revenue.
* **Justification:** Full system replacement costs $2.1M, whereas the baseline $\text{ALE}$ for MRI exploitation is $92,750. From T7, spending $90,000 annually on a dedicated Medical NAC platform yields a negative net value ($-\$6,525$). Accepting the residual risk for the remaining 18 months of the lease is financially rational.
* **Compensating Measure:** The workstation is placed on an isolated micro-segmented VLAN with strict firewall ACLs blocking outbound internet access and restricting lateral SMB/RDP communication to authorized PACS servers only.
* **Review Trigger:** Expiration of the $2.1M MRI scanner lease in 18 months, or discovery of a novel remote code execution (RCE) exploit actively targeting DICOM/PACS protocols in the wild.

#### 2. Absence of 24/7 Managed SOC (MSSP Coverage)

* **Risk ID:** `RISK-01` (Delayed Off-Hours Breach Detection and Containment)
* **Treatment Decision:** **Accept**
* **Authority:** **Chief Executive Officer (CEO) & Chief Financial Officer (CFO)**
* *Why:* Involves a significant recurring operational expense contract ($180,000/year) exceeding executive spending thresholds.
* **Justification:** Based on T7 cost-benefit analysis, an outsourced 24/7 Managed SOC costs $180,000 annually but only provides $120,000 in marginal $\text{ALE}$ reduction beyond internal controls, resulting in a negative net value of $-\$60,000$. Accepting off-hours detection latency is financially necessary under the current $120,000 total budget.
* **Compensating Measure:** Internal IT relies on automated endpoint containment via Sophos Intercept X (Control 5) and real-time email alerts from Wazuh SIEM (Control 3) routed to on-call administrative staff.
* **Review Trigger:** A security incident occurring during non-business hours that incurs greater than $50,000 in containment or remediation costs.

#### 3. Shadow IT / Unmanaged Personal NAS File Shares

* **Risk ID:** `RISK-03` (Negligent Insider Data Leakage via Unmonitored Storage)
* **Treatment Decision:** **Accept** (Residual Operational Risk)
* **Authority:** **Chief Medical Officer (CMO) & Chief Information Officer (CIO)**
* *Why:* Balances clinical efficiency and physician workflow demands against technical enforcement.
* **Justification:** Deploying specialized automated Data Loss Prevention (DLP) and Mobile Device Management (MDM) hardware agents across all physician-owned endpoints requires extensive capital and administrative overhead that yields sub-zero net return compared to core network controls.
* **Compensating Measure:** Implementation of strict Acceptable Use Policies (AUP), periodic manual network vulnerability scans, and USB/external storage blocking on all corporate domain-joined workstations via Sophos Intercept X.
* **Review Trigger:** Detection of unauthorized PHI transfer during routine Wazuh SIEM log audits or an external HIPAA audit finding.

### Part 3: The Boardroom Debate

#### James Chen (Security-First Mindset) — Argument for Mitigation

> "Accepting a Windows XP workstation on a $2.1M medical asset in 2026 is an unacceptable gamble with patient care and network safety. legacy OS endpoints serve as ideal bridgeheads for ransomware affiliates like BlackReef to establish persistence and pivot directly into our clinical subnets. While network segmentation helps, software vulnerabilities in unpatched XP kernels can be weaponized in seconds via automated exploits. We should immediately invest in inline protocol filtering or hardware micro-firewalls to fully isolate this machine, rather than waiting 18 months for a lease to expire."

#### Robert Kim (Cost-First Mindset) — Argument for Acceptance

> "We operate a health system, not a software laboratory, and our primary duty is maintaining fiscal solvency so we can keep our doors open to patients. Terminating a $2.1M scanner lease prematurely or spending $90,000 on niche Medical NAC tools that yield negative financial ROI directly hurts our operational margin. The $25,000 network segmentation control we already funded puts this machine on an isolated VLAN, cutting off lateral movement at a fraction of the cost. Accepting this residual risk for 18 months is a disciplined, rational business decision that protects our capital while maintaining adequate safety."

#### Board Verdict & Analysis

> **Verdict:** **Robert Kim's argument for acceptance is more compelling.**
> Robert’s reasoning correctly aligns with risk governance principles by treating cybersecurity as a risk-balancing discipline rather than an absolute mandate. James highlights a valid technical vulnerability, but his approach ignores the financial reality of negative net return ($\text{ALE}$ reduction vs. control cost) established in Task 7. Because Control 1 (VLAN Segmentation) successfully mitigates the primary blast radius by blocking lateral propagation, accepting the residual local risk on the MRI host for the remaining 18 months of the lease represents a defensible governance decision.
