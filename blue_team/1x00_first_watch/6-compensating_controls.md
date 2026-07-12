## 6: The Legacy Dilemma

### MRI Windows XP Critical Risk Analysis

**Why This Represents Critical Risk (3-4 sentences):**

The MRI workstation (Windows XP Embedded, running Siemens MAGNETOM control software) has not received security patches since April 2014 — over 11 years of zero vendor support. However, it sits on the same flat network (10.10.0.0/16) as 380+ workstations, medical IoT devices, and clinical servers, with unrestricted Layer 3 connectivity to the EHR database and billing systems. A single exploited workstation on the flat network can reach the MRI via ARP/DHCP, execute network-based attacks against Windows XP vulnerabilities (EternalBlue, MS17-010, Conficker), and pivot from the MRI into the larger infrastructure. The combination of unpatched OS + network accessibility + flat architecture + lack of segmentation means a determined attacker can compromise patient monitoring, medication delivery and clinical operations through a single legacy system that cannot be defended.

### Compensating Control Strategy

**Control 1: Network Segmentation (VLAN Isolation)**
- **Description:** Create a dedicated VLAN for the MRI and move its network port to an isolated access switch; configure firewall rules to allow ONLY PACS server communication on port 4006 (DICOM) to the MRI VLAN; deny all other inbound/outbound traffic
- **Category + Function:** Technical Preventive (with Detective component: firewall logs track all attempts to contact MRI)
- **How It Reduces Risk:** Isolates Windows XP from the flat network; any compromise is contained to the MRI VLAN only; attacker cannot pivot to EHR, billing or workstations; limits attack surface to PACS communication protocol only
- **Limitation:** Does not patch Windows XP vulnerabilities; only prevents network access to them. If PACS itself is compromised, the MRI becomes reachable.

**Control 2: Application Whitelisting on MRI Workstation**
- **Description:** Implement application control (e.g., AppLocker or similar) on the MRI workstation to allow ONLY the Siemens MAGNETOM application and essential OS services to execute; block all other binaries, scripts and tools
- **Category + Function:** Technical Preventive
- **How It Reduces Risk:** Even if Windows XP is exploited, arbitrary code execution is blocked; attacker cannot run malware, tools or shells; limits post-compromise capabilities; reduces risk of crypto-miner or ransomware persistence
- **Limitation:** Requires strict maintenance and testing with vendor (Siemens); risk of blocking legitimate updates or troubleshooting tools; must be monitored for bypasses

**Control 3: Dedicated Secure Gateway (Air-Gapped with One-Way Data Flow)**
- **Description:** Install a dedicated network appliance (e.g., Secure Cross-Domain Solution) between the MRI VLAN and the PACS server that enforces one-way data flow: PACS can push imaging studies TO the MRI but the MRI cannot initiate outbound connections; all data passes through content inspection/sanitization
- **Category + Function:** Technical Preventive (and Detective: appliance logs all attempts to violate one-way flow)
- **How It Reduces Risk:** Eliminates attack vector of MRI-to-PACS compromise; even if Windows XP is fully compromised, the MRI cannot reach back to PACS or other systems; attacker cannot exfiltrate data or pivot outward
- **Limitation:** High cost ($20K–50K+); requires ongoing management; potential performance impact on DICOM transfers; vendor support needed to ensure medical data integrity

**Control 4: Continuous Vulnerability Monitoring (Detective)**
- **Description:** Deploy agentless network-based vulnerability scanner that periodically probes the MRI for known Windows XP exploits (EternalBlue, MS17-010, etc.); generate alerts if vulnerabilities are detected as still exploitable
- **Category + Function:** Technical Detective
- **How It Reduces Risk:** Does not prevent exploitation but ensures the organization knows if the MRI becomes vulnerable (e.g., if segmentation is accidentally removed); triggers incident response; enables monitoring for actual attack attempts
- **Limitation:** Cannot prevent the vulnerability (XP is inherently vulnerable); only detects exposure; assumes incident response processes exist (they don't; see Exercise 5)

### Priority Implementation: Single Control with Greatest Risk Reduction

**Recommendation: Control 1 (VLAN Isolation + Firewall Rules)**

**Justification:**
- **Highest impact per dollar spent:** VLAN creation and firewall rule addition cost <$1K (minimal); eliminates 95% of network-based attack vectors
- **Immediately implementable:** No vendor coordination needed; no disruption to Siemens certification; no patient downtime
- **Addresses root cause:** The flat network IS the vulnerability; isolation breaks the link between Windows XP and the rest of MedDefense's infrastructure
- **Enables other controls:** Once segmented, Controls 2–4 become optional enhancements rather than critical

**If only one control can be implemented immediately:** Segment the MRI VLAN and restrict PACS communication. This single action reduces risk from Critical to High (localized to PACS only).
