## 3: The Walk-Through

### Structured Risk Analysis

**Observation 1: Server Room Access**
```
Vulnerability: 
  - Generic badge (same for all 2,000 employees) grants access to server room
  - No physical camera covering the door
  - No visitor log; no access audit trail
  - Shared corridor with cafeteria traffic provides concealment

Threat: 
  - Disgruntled employee, contractor, or unauthorized visitor could enter undetected
  - Custodial staff or temp workers gain unrestricted access to critical infrastructure
  - After-hours access (7 PM - 7 AM) when single guard is absent or at main entrance

Impact: 
  - Confidentiality: Attacker directly accesses EHR database drives (ehr-db-01), billing server (billing-srv-01); exfiltrates patient records
  - Integrity: Attacker modifies or destroys servers; plants malware (as evidenced by crypto-miner found in Exercise 2)
  - Availability: Attacker powers down or physically damages servers; 350-bed hospital loses EHR, billing, imaging services

Severity: CRITICAL
  - Server room contains all critical clinical infrastructure; no compensating controls (no armed alarm, no video, no access log)
```

**Observation 2: Network Closet Unprotected**
```
Vulnerability: 
  - Unlocked network closet containing Cisco switches and patch panels
  - Credentials (username/password) laminated and taped to wall
  - No audit of who has accessed the closet or credentials
  - Positioned on high-traffic second floor

Threat: 
  - Any staff member or visitor can enter, view credentials and access network management interface
  - Attacker modifies switch VLANs, creates rogue access points, redirects traffic (ARP spoofing)
  - Remote access to switch interface enables network segmentation bypass

Impact: 
  - Confidentiality: Attacker sniffs unencrypted traffic; intercepts patient data, credentials, imaging files
  - Integrity: Attacker reroutes traffic to malicious host; modifies switch configuration; injects malicious devices
  - Availability: Attacker disables network segments; disconnects critical VLANs; causes network partition

Severity: CRITICAL
  - Direct access to network core infrastructure; credentials on wall eliminate need for sophisticated attack
```

**Observation 3: Nurse Station EHR Session**
```
Vulnerability: 
  - EHR session left logged in and idle for 15+ minutes
  - No screen lock enforced
  - Sign discourages logout ("for efficiency")
  - Patient medical record (sensitive data) visible on screen
  - Unattended workstation in semi-public nurse station area

Threat: 
  - Any hospital staff, visitor or patient can sit at workstation
  - Attacker can view, modify or download visible patient record
  - Threat actor can assume authenticated session; perform actions as logged-in clinician

Impact: 
  - Confidentiality: Patient record (PHI) visible to unauthorized person; record may be photographed, documented or discussed
  - Integrity: Attacker modifies prescription, diagnosis or dosage in the patient's EHR; clinical decisions based on false data
  - Availability: Attacker locks workstation; forces clinical staff to find alternative; disrupts workflow; patient care delayed

Severity: CRITICAL
  - Patient safety directly at risk; policy actively discourages proper session handling; recurring vulnerability if cultural norm
```

**Observation 4: Medical IoT on Flat Network**
```
Vulnerability: 
  - Vital signs monitor (IP 10.10.3.47) on same network segment as workstations (10.10.0.0/16 flat)
  - No network segmentation between clinical devices and general endpoints
  - Firmware v2.1.3 from 2019; no documented patch history
  - Device runs real-time patient monitoring; network accessible without firewall rules

Threat: 
  - Network compromise (workstation malware, rogue user, physical access) provides direct access to monitor
  - Attacker with network access can modify monitor parameters, disable alerts or corrupt vital signs display
  - Supply-chain or firmware vulnerability exploitable without segmentation

Impact: 
  - Integrity: Attacker modifies displayed vital signs (e.g., raises heart rate reading 40 bpm); clinician responds to false data
  - Availability: Attacker disables monitor; patient becomes unmonitored; alerts fail to trigger
  - Confidentiality: Monitor transmits unencrypted patient data (HR, BP, SpO2) to medical record system

Severity: CRITICAL
  - Directly affects patient safety; modification of vital signs can lead to incorrect treatment, medication or discharge decisions
```

**Observation 5: Fire Exit Propped Open**
```
Vulnerability: 
  - Fire exit between public area and restricted admin wing propped open continuously
  - No access control (badge reader or alarm) on this door
  - Provides unmonitored path to IT department and security leadership offices
  - "Staff passage" sign normalizes violation of security boundary

Threat: 
  - Unauthorized visitor, contractor or intruder gains unrestricted access to IT and security offices
  - Attacker can access unattended workstations, physical documents (password lists, org charts, strategic plans)
  - Social engineering: attacker walks through as if they belong; no checkpoint or challenge

Impact: 
  - Confidentiality: Access to James Chen's office, IT administrative areas; documents on desks; system credentials
  - Integrity: Attacker plants USB malware on IT workstations; modifies configurations; accesses sensitive systems
  - Availability: Attacker gains physical access to IT infrastructure and security operations; disables controls

Severity: HIGH
  - Compromises security perimeter; directly enables physical access to security leadership and IT; violates HIPAA physical safeguards
```
