# 15. The Gap-Threat Correlation

### Gap ID: Net-04

* **Description**: Flat network architecture
* **Original Risk Level**: High
* **Threat Actors**: Ransomware (BlackReef), APT (Nation-State), Insider
* **Kill Chains**: 1, 2, 5
* **Scenarios**: 1, 3
* **Updated Risk Level**: **Critical**
* **Justification**: This gap is a universal enabler for lateral movement in every scenario and kill chain.

### Gap ID: IAM-05

* **Description**: Lack of privileged account monitoring
* **Original Risk Level**: High
* **Threat Actors**: Ransomware (BlackReef), Insider
* **Kill Chains**: 1, 3
* **Scenarios**: 1
* **Updated Risk Level**: **Critical**
* **Justification**: Directly facilitates credential abuse and domain compromise in ransomware campaigns.

### Gap ID: Net-01

* **Description**: Unpatched VPN/Perimeter
* **Original Risk Level**: High
* **Threat Actors**: Ransomware (BlackReef)
* **Kill Chains**: 1
* **Scenarios**: 1
* **Updated Risk Level**: **High**
* **Justification**: Critical initial access point for external threat actors.

### Gap ID: Sys-01

* **Description**: Unsupported OS (XP)
* **Original Risk Level**: Medium
* **Threat Actors**: APT (Nation-State)
* **Kill Chains**: 5
* **Scenarios**: 3
* **Updated Risk Level**: **High**
* **Justification**: Upgraded due to its role as a persistent, hard-to-detect foothold for high-tier APTs.

### Gap ID: SEC-02

* **Description**: Lack of file integrity/DLP
* **Original Risk Level**: Medium
* **Threat Actors**: Insider
* **Kill Chains**: 3
* **Scenarios**: 2
* **Updated Risk Level**: **High**
* **Justification**: Essential for detecting and blocking data exfiltration by insiders.

### Gap ID: VDR-01

* **Description**: Lack of vendor management
* **Original Risk Level**: Medium
* **Threat Actors**: APT (Nation-State)
* **Kill Chains**: 5
* **Scenarios**: 3
* **Updated Risk Level**: **Medium**
* **Justification**: High impact, but only relevant to specific supply chain attack vectors.

### Gap ID: IAM-03

* **Description**: Failed IT offboarding SLA
* **Original Risk Level**: Low
* **Threat Actors**: Insider
* **Kill Chains**: None
* **Scenarios**: 2
* **Updated Risk Level**: **Medium**
* **Justification**: Upgraded because threat analysis highlights the high probability of abuse during termination.

# Re-prioritized Gap List

* **Net-04** (Flat network architecture) - **Critical** (Status: Moved Up)
* **IAM-05** (Lack of privileged account monitoring) - **Critical** (Status: Moved Up)
* **Net-01** (Unpatched VPN/Perimeter) - **High** (Status: No Change)
* **Sys-01** (Unsupported OS (XP)) - **High** (Status: Moved Up)
* **SEC-02** (Lack of file integrity/DLP) - **High** (Status: Moved Up)
* **VDR-01** (Lack of vendor management) - **Medium** (Status: No Change)
* **IAM-03** (Failed IT offboarding SLA) - **Medium** (Status: Moved Up)

# The Critical Three

1. **Net-04** (Flat Network)
2. **IAM-05** (Privileged Account Monitoring)
3. **Sys-01** (Unsupported OS) - *Due to its criticality in persistent APT threats*

# The Surprise

**IAM-03 (Failed IT offboarding SLA)**: Initially rated Low as a procedural inefficiency. Threat analysis reveals this is an easily exploitable window for insiders to access systems post-termination, directly facilitating the 'Quiet Departure' scenario, justifying its upgrade to Medium.
