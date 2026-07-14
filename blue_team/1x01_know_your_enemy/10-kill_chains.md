# 10. The Kill Chains

## Kill Chain #1: Ransomware Encrypts EHR

* **Threat Actor**: Ransomware Group (BlackReef)
* **Target Asset**: EHR Database (ehr-db-01)
* **Expected Impact**: Clinical operations halted; Confidentiality/Availability lost.

### Step 1 - Initial Access

* **Vector**: VPN Exploit
* **Surface**: External
* **Detail**: Attacker exploits unpatched CVE on FortiGate VPN appliance.

### Step 2 - Establish Foothold

* **Action**: Deploys Cobalt Strike beacon.
* **MedDefense Weakness**: Lack of endpoint EDR/AV monitoring.

### Step 3 - Lateral Movement / Escalation

* **Action**: Pivots via flat network to domain controller.
* **MedDefense Weakness**: Flat network architecture (Net-04).

### Step 4 - Objective Execution

* **Action**: Deploys ransomware via GPO.
* **Data/System Affected**: Encrypts ehr-db-01.

### Step 5 - Impact

* **Business Impact**: Total loss of access to patient records; 11+ days of downtime.
* **CIA Pillars**: Availability (Loss), Confidentiality (Data Leak).

**Gaps Exploited**: Net-01, Net-04, IAM-05

**Break Points**: 1. Step 1 (Patching/WAF), 2. Step 3 (Network Segmentation).


## Kill Chain #2: Medical IoT Sabotage

* **Threat Actor**: Ransomware Group (BlackReef)
* **Target Asset**: Medical IoT (Alaris Pumps)
* **Expected Impact**: Patient harm; Availability/Integrity lost.

### Step 1 - Initial Access

* **Vector**: Default Credentials
* **Surface**: Internal
* **Detail**: Attacker logs in via default manufacturer credentials.

### Step 2 - Establish Foothold

* **Action**: Establishes persistent network bridge.
* **MedDefense Weakness**: Lack of device monitoring.

### Step 3 - Lateral Movement / Escalation

* **Action**: Scans clinical subnet for pump control interfaces.
* **MedDefense Weakness**: Flat network architecture (Net-04).

### Step 4 - Objective Execution

* **Action**: Modifies pump flow settings.
* **Data/System Affected**: Alaris pump dosage configurations.

### Step 5 - Impact

* **Business Impact**: High risk of patient injury; massive reputational damage.
* **CIA Pillars**: Integrity (Loss), Availability (Loss).

**Gaps Exploited**: IAM-04, Net-04

**Break Points**: 1. Step 1 (Change Default Credentials), 2. Step 3 (Network Segmentation).

## Kill Chain #3: EHR Data Exfiltration

* **Threat Actor**: Malicious Insider
* **Target Asset**: EHR Database (ehr-db-01)
* **Expected Impact**: Regulatory breach; Confidentiality lost.

### Step 1 - Initial Access

* **Vector**: Insider (Malicious)
* **Surface**: Internal
* **Detail**: Authorized user accesses database during shift.

### Step 2 - Establish Foothold

* **Action**: Stages data locally.
* **MedDefense Weakness**: No file integrity monitoring.

### Step 3 - Lateral Movement / Escalation

* **Action**: Exfiltrates to cloud storage.
* **MedDefense Weakness**: No egress filtering on firewall.

### Step 4 - Objective Execution

* **Action**: Transfers 50,000 records.
* **Data/System Affected**: Exporting full patient EHR database.

### Step 5 - Impact

* **Business Impact**: HIPAA fines; loss of patient trust.
* **CIA Pillars**: Confidentiality (Loss).

**Gaps Exploited**: SEC-02, IAM-05

**Break Points**: 1. Step 2 (DLP/Monitoring), 2. Step 3 (Egress Filtering).

## Kill Chain #4: BEC and Identity Theft

* **Threat Actor**: Unskilled/Opportunistic Attacker
* **Target Asset**: O365 Email (Identity)
* **Expected Impact**: Financial loss; Confidentiality/Integrity lost.

### Step 1 - Initial Access

* **Vector**: Phishing
* **Surface**: Human
* **Detail**: User clicks malicious link in fake invoice email.

### Step 2 - Establish Foothold

* **Action**: Harvests session token.
* **MedDefense Weakness**: Lack of FIDO2-based MFA.

### Step 3 - Lateral Movement / Escalation

* **Action**: Accesses mailboxes/contacts.
* **MedDefense Weakness**: Excessive mailbox permissions.

### Step 4 - Objective Execution

* **Action**: Sends fake wire instructions.
* **Data/System Affected**: Corporate funds diverted.

### Step 5 - Impact

* **Business Impact**: Financial loss; organizational compromise.
* **CIA Pillars**: Integrity (Loss), Confidentiality (Loss).

**Gaps Exploited**: IAM-02, TRN-01

**Break Points**: 1. Step 1 (Security Awareness Training), 2. Step 2 (MFA Implementation).

## Kill Chain #5: MRI System Persistence

* **Threat Actor**: Nation-State APT
* **Target Asset**: MRI Workstation
* **Expected Impact**: Long-term espionage/disruption; Integrity/Availability lost.

### Step 1 - Initial Access

* **Vector**: Supply Chain Compromise
* **Surface**: External
* **Detail**: Malicious firmware update from vendor.

### Step 2 - Establish Foothold

* **Action**: Installs rootkit on XP OS.
* **MedDefense Weakness**: Unsupported OS (Sys-01).

### Step 3 - Lateral Movement / Escalation

* **Action**: Pivots to clinical network.
* **MedDefense Weakness**: Flat network architecture (Net-04).

### Step 4 - Objective Execution

* **Action**: Monitors imaging traffic.
* **Data/System Affected**: Capturing patient diagnostic images.

### Step 5 - Impact

* **Business Impact**: Long-term stealth surveillance.
* **CIA Pillars**: Confidentiality (Loss), Integrity (Loss).

**Gaps Exploited**: Sys-01, Net-04, VDR-01

**Break Points**: 1. Step 1 (Vendor Audit/Supply Chain Mgmt), 2. Step 2 (Endpoint Security/Isolation).
