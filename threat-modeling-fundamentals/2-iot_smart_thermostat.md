# IoT Smart Thermostat Threat Modeling

## Requirements Overview

### Documentation Standards

Each analysis must include clear structure and realistic attack scenarios

| Component | Details |
|-----------|---------|
| **Threat Analysis** | Description + Attack Scenario + Impact + Likelihood + Mitigation |
| **Risk Assessment** | DREAD methodology with formula work shown |
| **Citations** | External resources properly referenced |
| **Formatting** | Markdown tables, lists, code blocks, diagrams |
| **Technical Depth** | Visual architecture & attack chains required |

### Quality Standards

- Realistic attack scenarios based on IoT vulnerabilities
- Specific, actionable mitigations (not generic advice)
- Show all calculations with reasoning
- Consider real-world constraints (device hardware, battery life, cost)
- Professional presentation suitable for product teams

---

## Task: IoT Smart Thermostat

### System Overview

**Device:** Connected Thermostat | **Network:** Home Wi-Fi | **Control:** Mobile App | **Updates:** OTA Firmware

```
System Architecture:

Mobile App
    |
    | HTTPS REST API
    |
Cloud Backend
    |
    | Commands/Updates
    |
Smart Thermostat Device
    |
    +-- Wi-Fi Module
    +-- Temperature Sensor
    +-- Heating/Cooling Control
    +-- Firmware Storage
    +-- Debug Interface (UART/JTAG)
```

---

## Question 1: Five IoT-Specific Threats

IoT devices face unique vulnerabilities not found in traditional web applications due to hardware constraints, physical accessibility, and embedded systems architecture.

---

### Threat 1: Weak Default Credentials

| Element | Details |
|---------|---------|
| **Category** | Authentication/Access Control |
| **Description** | Device ships with hardcoded default username/password (e.g., admin/12345) |
| **Why IoT-Specific** | Web apps don't have hardcoded credentials; IoT firmware often does |
| **Attack Scenario** | Attacker connects to device via telnet/SSH using default credentials; gains full control over thermostat; raises temperature to damage home or steals Wi-Fi network access |
| **Potential Impact** | Unauthorized device control; network pivot point to hack other home devices; privacy breach (temperature patterns reveal when home is empty) |
| **Likelihood** | VERY HIGH - common across IoT ecosystem |
| **Real-World Example** | Mirai botnet exploited default credentials in 600,000+ IoT devices |
| **Mitigation** | Force unique password creation during device setup; No hardcoded credentials in firmware; Disable default accounts after first login; Implement rate limiting on authentication attempts |

---

### Threat 2: Unencrypted Communications

| Element | Details |
|---------|---------|
| **Category** | Confidentiality/Integrity |
| **Description** | Device sends temperature data and commands over Wi-Fi in plaintext (no TLS encryption) |
| **Why IoT-Specific** | Resource-constrained devices often skip encryption to save CPU/battery; older IoT devices predate modern security standards |
| **Attack Scenario** | Attacker performs man-in-the-middle attack on home Wi-Fi; captures unencrypted messages; intercepts heating commands and changes temperature; observes patterns (home empty during work hours) for burglary targeting |
| **Potential Impact** | Temperature manipulation affecting comfort and safety; privacy leak (home occupancy patterns); device hijacking |
| **Likelihood** | HIGH - common in budget IoT devices |
| **Real-World Example** | Nest thermostat initially lacked encryption on local network communications |
| **Mitigation** | Enforce TLS 1.2+ for all cloud communications; Implement local encryption for Wi-Fi commands; Use certificate pinning to prevent MITM; Validate all received commands server-side |

---

### Threat 3: Firmware Vulnerabilities (No Code Signing)

| Element | Details |
|---------|---------|
| **Category** | Integrity/Code Execution |
| **Description** | Firmware updates accepted without cryptographic verification; attacker can flash malicious firmware |
| **Why IoT-Specific** | Firmware is the device's entire operating system; one vulnerability compromises everything; harder to patch than web apps |
| **Attack Scenario** | Attacker intercepts OTA update; crafts malicious firmware with backdoor; device accepts and installs firmware without verification; attacker gains persistent control; uses device to attack other home networks |
| **Potential Impact** | Complete device compromise; persistent backdoor; lateral movement to other smart home devices; botnet recruitment |
| **Likelihood** | MEDIUM-HIGH - especially on budget devices |
| **Real-World Example** | TP-Link routers accepted unsigned firmware; widely exploited |
| **Mitigation** | Digitally sign all firmware with private key; Device verifies signature before installing; Use secure boot to ensure signed firmware only; Implement rollback protection |

---

### Threat 4: Physical Debug Interfaces (UART/JTAG)

| Element | Details |
|---------|---------|
| **Category** | Physical Security/Unauthorized Access |
| **Description** | Device has exposed debug ports allowing direct access to internals |
| **Why IoT-Specific** | Embedded devices often have debug ports left in place for manufacturing; impossible to hide debug interface with physical access |
| **Attack Scenario** | Attacker opens thermostat casing; accesses UART/JTAG pins; connects USB adapter; reads device firmware directly from memory; dumps encryption keys; extracts Wi-Fi password from storage; achieves complete compromise |
| **Potential Impact** | Complete credential extraction; firmware theft; encryption key compromise; persistent backdoor installation |
| **Likelihood** | MEDIUM - requires physical access but simple tools ($10 USB adapter) |
| **Real-World Example** | Most consumer IoT devices ship with accessible debug ports |
| **Mitigation** | Disable debug ports after manufacturing (fuse bits); Encrypt sensitive data in memory/storage; Use secure enclave for key storage; Implement tamper detection sensors; Physically cover debug ports |

---

### Threat 5: No Update Mechanism / Outdated Firmware

| Element | Details |
|---------|---------|
| **Category** | Patch Management / Obsolescence |
| **Description** | Device cannot receive firmware updates; stays vulnerable forever |
| **Why IoT-Specific** | Many IoT devices never receive patches; users lack ability/knowledge to manually update |
| **Attack Scenario** | Vulnerability discovered in temperature sensor protocol; thermostat cannot be patched; attacker exploits known vulnerability months/years later; affects thousands of unpatched devices |
| **Potential Impact** | Permanent vulnerability window; devices become liability after 2-3 years; difficult to remediate across user base |
| **Likelihood** | VERY HIGH - industry norm for budget IoT |
| **Real-World Example** | Billions of IoT devices never receive security updates |
| **Mitigation** | Implement robust OTA update mechanism; Push security patches automatically; Design for long-term support (5+ years); Allow user rollback to previous stable version; Maintain update servers long-term |

---

## Question 2: Physical Access Attack Chain

### Scenario: Attacker Gains Physical Access to Device

Attack happens when device is unattended in home, installed in accessible location (thermostat typically in hallway/living room).

---

### Step 1: Initial Physical Inspection

```
Attacker Action: Visual examination and equipment research

1. Photograph device internals (look up PCB markings)
2. Identify microcontroller model (e.g., ARM Cortex-M4)
3. Search online for datasheet and pinouts
4. Identify debug ports: UART (serial), JTAG (Joint Test Action Group), SWD (Serial Wire Debug)
5. Note additional hardware: encryption chip, TPM, secure enclave

Tools Required: Smartphone camera, internet access, free datasheets
Cost: Free
Time: 5-15 minutes
```

---

### Step 2: Access Debug Interface

```
Attacker Action: Connect to debug port (UART most common)

Hardware Setup:
├─ USB-to-Serial adapter (~$10 on Amazon)
├─ Jumper wires
├─ Small soldering iron (optional, if pins must be exposed)
└─ Laptop with terminal software

Connection Process:
1. Open thermostat casing (usually 4 screws, no tamper protection)
2. Solder or clip to UART pins (TX, RX, GND)
3. Connect USB adapter to laptop
4. Open terminal: $ minicom /dev/ttyUSB0 115200
5. Receive boot messages: "Thermostat v2.1.4 loading..."
6. Achieve shell access: $ telnet localhost:23 (if enabled)

Tools Required: USB adapter, jumper wires, soldering iron
Cost: $20-40
Time: 15-30 minutes
```

---

### Step 3: Extract Firmware and Credentials

```
Attacker Action: Read device memory and extract sensitive data

Firmware Extraction Via Debug Port:
├─ Command: $ readmem 0x0 0x400000 firmware.bin
├─ Captures entire firmware image (4MB typical)
├─ No encryption protection (or weak encryption)

Credentials in Memory:
├─ Wi-Fi SSID and password (stored in plaintext)
├─ Cloud API credentials
├─ Encryption keys (if present)
├─ Device authentication tokens

Example Output:
  SSID: "HomeNetwork"
  Password: "MyWiFi123"
  API_Key: "d4f7e8c3b2a1f9e6"
  Device_Token: "abc123def456..."

Alternative: Physical Memory Dump
├─ Attach JTAG probe (more advanced, $100+ tool)
├─ Dump entire RAM and flash memory
├─ Use chipoff technique (remove memory chip, read directly)

Tools Required: Terminal software, optionally JTAG probe
Cost: Free to $100+
Time: 5-20 minutes
```

---

### Step 4: Hijack Device and Network

```
Attacker Action: Take control of thermostat and home network

Immediate Actions:
1. Change admin password: $ passwd root
2. Install backdoor: Copy malicious script to /opt/app
3. Create new user account for persistence
4. Disable firmware signature verification (if possible)
5. Modify startup scripts to execute backdoor on boot

Achieve Persistence:
- Backdoor survives device reboot
- Attacker can access remotely if network access obtained
- Cloud account compromise enables remote control

Network Exploitation:
- Extract Wi-Fi credentials from device
- Connect to home Wi-Fi with captured password
- Lateral movement to other smart home devices (locks, cameras, alexa)
- Perform network scanning: $ arp-scan 192.168.1.0/24
- Pivot to router admin panel
- Establish command and control channel

Tools Required: Linux terminal knowledge
Cost: Free
Time: 10-20 minutes
```

---

### Complete Attack Chain Timeline

| Step | Time | Attacker Capability | Impact |
|------|------|------------------|--------|
| 1 | 15 min | Physical inspection | Identifies device architecture |
| 2 | 30 min | Debug port access | Gains shell/command interface |
| 3 | 20 min | Firmware extraction | Obtains credentials, encryption keys |
| 4 | 20 min | Complete compromise | Persistent backdoor, network access |
| **TOTAL** | **85 minutes** | **Full device and network control** | **Complete home automation compromise** |

---

### Potential Impacts

| Impact Category | Details |
|-----------------|---------|
| **Immediate Impacts** | Temperature manipulation (discomfort); heating/cooling disabled (HVAC sabotage) |
| **Privacy Impacts** | Home occupancy patterns tracked; temperature schedule reveals lifestyle |
| **Network Impacts** | Home Wi-Fi compromised; lateral movement to cameras, locks, other devices |
| **Long-term Impacts** | Persistent backdoor; botnet recruitment; used to attack other networks; ransomware distribution |
| **Physical Impacts** | Comfort/safety (elderly at risk from extreme temperatures); property damage potential |

---

## Question 3: OTA Update Security Design

Over-the-air (OTA) firmware updates are critical for patching vulnerabilities, but they introduce new attack surface if not properly secured.

---

### Essential Security Requirements

### Requirement 1: Code Signing and Verification

```
Purpose: Ensure firmware authenticity and integrity

Implementation:

1. Manufacturer Code Signing
   ├─ Developer creates firmware binary (thermostat_v2.1.5.bin)
   ├─ Sign with manufacturer's private RSA-2048 key
   ├─ Output: firmware.bin + signature.sig (cannot forge without key)
   └─ Private key stored in secure hardware security module (HSM)

2. Device Firmware Verification
   ├─ Device stores manufacturer's public certificate
   ├─ On update download, verify signature: cryptography.verify(firmware, signature, public_key)
   ├─ If signature invalid: REJECT update immediately
   ├─ Do NOT install unsigned firmware under any circumstances
   └─ Abort update and alert user

3. Chain of Trust
   ├─ Root certificate authority (CA) signs manufacturer certificate
   ├─ Device verifies entire certificate chain
   ├─ Prevents attacker from using fake certificate
   └─ Standard PKI infrastructure

Code Example:
   function verify_firmware_signature(firmware_data, signature, public_key):
     hash = SHA256(firmware_data)
     is_valid = RSA_verify(hash, signature, public_key)
     if NOT is_valid:
       log_error("FIRMWARE SIGNATURE VERIFICATION FAILED")
       return FALSE
     return TRUE

Benefit: Prevents installation of malicious firmware
```

---

### Requirement 2: Encrypted Update Channels

```
Purpose: Protect firmware in transit from interception/modification

Implementation:

1. TLS Encryption
   ├─ All firmware downloads use HTTPS/TLS 1.2+ (not HTTP)
   ├─ Device verifies server certificate (certificate pinning)
   ├─ Man-in-the-middle protection
   └─ Prevents attacker from swapping firmware during download

2. Server Authentication
   ├─ Device connects only to manufacturer's update server
   ├─ Server certificate pinned in firmware (hardcoded public key hash)
   ├─ Prevents connection to fake update server
   └─ Protects against DNS hijacking attacks

3. Firmware Encryption
   ├─ Optional additional layer: encrypt firmware in storage
   ├─ Decrypt during update verification
   └─ Adds security even if firmware file leaked

Connection Flow:
   Device                               Cloud Server
   |                                          |
   +---> HTTPS Connection (TLS 1.2)         |
   |     (verify cert pinning)              |
   |                                         |
   |<--- Encrypted Firmware Download <------+
   |     (download.bin encrypted)           |
   |                                         |
   +---> Verification Complete              |
   |     (signature and integrity ok)       |
   |                                         |

Benefit: Prevents interception and tampering during download
```

---

### Requirement 3: Secure Boot

```
Purpose: Ensure device only runs signed firmware

Implementation:

1. Bootloader Protection
   ├─ Bootloader is read-only (burned into ROM)
   ├─ Bootloader itself is signed and verified
   ├─ Device CPU verifies bootloader signature on every boot
   └─ Cannot be replaced or bypassed

2. Firmware Verification at Boot
   ├─ Before executing firmware, verify signature
   ├─ If verification fails: halt boot process
   ├─ Device cannot run unsigned or tampered firmware
   └─ Protection against physical tampering (memory modification)

3. Trusted Execution Environment (TEE)
   ├─ Use device's secure processor (if available)
   ├─ Store cryptographic keys in secure enclave
   ├─ Keys never exposed in regular memory
   └─ Prevents key extraction even with debug access

Boot Sequence:
   Power On
      |
      v
   Verify Bootloader Signature
      |
   If invalid --> HALT (safety failure)
      |
      v
   Load Bootloader Code
      |
      v
   Verify Firmware Signature
      |
   If invalid --> HALT (safety failure)
      |
      v
   Load and Execute Firmware
      |
   v
   Device Operational

Benefit: Prevents installation and execution of unauthorized code
```

---

### Requirement 4: Rollback Protection

```
Purpose: Prevent attacker from downgrading to older vulnerable firmware

Implementation:

1. Version Checking
   ├─ Each firmware has version number (e.g., v2.1.5)
   ├─ Device stores current version in protected storage
   ├─ New firmware must have higher version number
   ├─ Device rejects downgrade attempts
   └─ Example: Cannot update from v2.1.5 to v2.1.4

2. Rollback Counter
   ├─ Counter incremented with each legitimate update
   ├─ Stored in non-volatile memory (resistant to tampering)
   ├─ Update rejected if counter decreases
   └─ Prevents reverting to old vulnerable version

3. Secure Rollback Storage
   ├─ Version/counter in device secure enclave
   ├─ Protected from physical tampering
   ├─ Updated atomically (all or nothing)
   └─ Recovery from power loss mid-update

Protection Against:
- Attacker downgrading to firmware with known vulnerability
- Attacker installing old version without security patches
- Forced rollback after compromise

Example Attack Prevented:
  Scenario: v2.1.4 has SQL injection vulnerability (patched in v2.1.5)
  Attacker tries: Install v2.1.4 to re-exploit vulnerability
  Device blocks: "v2.1.4 < current v2.1.5, rejected"
  Result: Attacker cannot reintroduce old vulnerabilities

Benefit: Ensures security improvements cannot be undone
```

---

### Requirement 5: Update Integrity Verification

```
Purpose: Verify firmware has not been corrupted during download

Implementation:

1. Cryptographic Hash
   ├─ Manufacturer calculates SHA-256 hash of firmware
   ├─ Hash published alongside firmware
   ├─ Device recalculates hash after download
   ├─ Hash mismatch = corrupted file (abort update)
   └─ Detects accidental corruption and tampering

2. Checksum Verification
   ├─ Additional CRC32 checksum for quick check
   ├─ Fast detection of incomplete downloads
   └─ Prevents installation of partial firmware

3. Size Verification
   ├─ Expected firmware size hardcoded in update manifest
   ├─ Device verifies downloaded size matches
   ├─ Rejects undersized or oversized files
   └─ Simple check prevents buffer overflows

Verification Process:
   Downloaded File (firmware.bin)
      |
      v
   Calculate SHA-256 hash
      |
      v
   Compare to published hash
      |
   If match  --> Proceed to signature verification
   If mismatch --> ABORT (file corrupted)

Benefit: Ensures firmware integrity before installation
```

---

### Requirement 6: Safe Update Process

```
Purpose: Protect device if update is interrupted or fails

Implementation:

1. Atomic Update (All or Nothing)
   ├─ Write new firmware to backup partition (not active)
   ├─ Verify new firmware completely and correctly
   ├─ Only after verification: switch to new partition
   ├─ If power loss during update: old firmware still active
   └─ Device never runs partial/corrupted firmware

2. Watchdog Timer
   ├─ Device has watchdog that reboots if hung
   ├─ If update hangs: device auto-reboots to safe state
   ├─ Prevents device stuck in update process
   └─ Recovery possible without manual intervention

3. Rollback on Failure
   ├─ If new firmware fails to boot: auto-revert to old version
   ├─ Device detects boot failure (timeout detection)
   ├─ Automatically restores previous working firmware
   ├─ User notified of update failure
   └─ Manual retry available

Update Storage Layout:
   Flash Memory
   ├─ Bootloader (immutable)
   ├─ Active Firmware Partition (v2.1.5) [Currently Running]
   └─ Backup Firmware Partition (empty or v2.1.4)
   
   During Update:
   ├─ Download new firmware to Backup partition
   ├─ Verify completely
   ├─ Swap partitions (atomic operation)
   ├─ If crash: still have v2.1.5 in old partition
   └─ Recovery automatic

Benefit: Safe and reliable updates with recovery capability
```

---

### Requirement 7: User Notification and Control

```
Purpose: Keep user informed and give control over update timing

Implementation:

1. Update Notifications
   ├─ Notify user before installing critical security updates
   ├─ Explain update purpose (bug fix, security patch, feature)
   ├─ Show estimated update duration
   └─ Get user approval before proceeding

2. Update Scheduling
   ├─ Allow user to choose update time (e.g., 2 AM)
   ├─ Avoid updating during peak usage times
   ├─ Defer non-critical updates
   └─ Critical security updates may auto-install

3. Update Status
   ├─ Display progress: "Downloading... 45%"
   ├─ Show estimated time remaining
   ├─ Report status: success, failure, rollback
   └─ Log all update events for troubleshooting

4. Manual Update Option
   ├─ Users can manually check for updates
   ├─ Option to update immediately if available
   └─ For users who want to control timing

Notification Flow:
   Cloud Server: "Security patch available"
      |
      v
   Device: "Security Update Available"
           [Install Now] [Later] [Details]
      |
      v
   User: [Later] (chooses 2 AM automatic install)
      |
      v
   Device: Schedules update for 2 AM
      |
      v
   2 AM: Automatic update execution
      |
      v
   Device: "Update successful, reboot in 5 min"
      |
      v
   User: [Reboot Now] or wait for automatic reboot

Benefit: User control and awareness
```

---

## Complete OTA Security Architecture

### Update Flow Diagram

```
Step 1: Check for Updates
├─ Device queries: GET /api/firmware/check?device_id=XYZ
├─ Server responds: {"version": "2.1.5", "size": 4194304, "hash": "abc123..."}
└─ Device compares: 2.1.5 > current 2.1.4 → Update available

Step 2: Notify User
├─ Display: "Security update available (10 MB)"
├─ User selects: "Install at 2 AM"
└─ Device schedules task

Step 3: Download Firmware
├─ Device: HTTPS GET /firmware/thermostat_v2.1.5.bin
├─ Server: Sends encrypted firmware (TLS protected)
├─ Device: Stores to backup partition
└─ Device: Verifies download size and CRC

Step 4: Verify Firmware Integrity
├─ Calculate SHA-256 hash of downloaded file
├─ Compare to server-provided hash
└─ If mismatch: Delete, alert user, abort

Step 5: Verify Firmware Signature
├─ Extract signature from firmware header
├─ Verify signature using manufacturer's public key
├─ If invalid: Delete firmware, abort, alert user
└─ If valid: Proceed

Step 6: Atomic Swap
├─ Device bootloader: Set new partition as active
├─ Atomic operation (no power loss corruption)
├─ Reboot device
└─ Boot with new firmware

Step 7: Boot Verification
├─ Bootloader verifies new firmware signature
├─ New firmware starts successfully
├─ Device sends: "Update successful"
├─ Server logs: Version 2.1.5 active
└─ User notified: "System updated to v2.1.5"

Step 8: Failure Recovery (if needed)
├─ If new firmware fails to boot
├─ Bootloader detects failure
├─ Automatically boots old firmware (v2.1.4)
├─ Device notifies server: "Update failed, rolled back"
└─ User notified of failure, can retry later
```

---

## OTA Security Checklist

| Security Control | Requirement | Implementation |
|------------------|-------------|-----------------|
| Code Signing | Mandatory | RSA-2048 signature on all firmware |
| Signature Verification | Mandatory | Device must reject unsigned firmware |
| Encrypted Channel | Mandatory | HTTPS/TLS 1.2+ for all downloads |
| Certificate Pinning | Mandatory | Hardcode update server public key |
| Version Checking | Mandatory | Block downgrade to older versions |
| Rollback Counter | Mandatory | Non-volatile counter prevents rollback |
| Hash Verification | Mandatory | SHA-256 integrity check post-download |
| Atomic Update | Mandatory | Dual-partition design, all-or-nothing |
| Secure Boot | Mandatory | Bootloader verifies firmware on each boot |
| Safe Failure | Mandatory | Auto-revert to previous version on failure |
| User Notification | Mandatory | Inform user before critical updates |
| Update Scheduling | Recommended | Allow user to choose update timing |
| Watchdog Timer | Recommended | Auto-reboot if update hangs |
| Audit Logging | Recommended | Log all update attempts and status |

---

## Implementation Priority

| Priority | Control | Timeline |
|----------|---------|----------|
| Critical (Phase 1) | Code signing, signature verification, secure boot | Weeks 1-2 |
| Critical (Phase 1) | TLS encryption, atomic updates, hash verification | Weeks 1-2 |
| High (Phase 2) | Version checking, rollback protection | Weeks 3-4 |
| High (Phase 2) | User notification, update scheduling | Weeks 3-4 |
| Medium (Phase 3) | Watchdog timer, audit logging, failure recovery | Weeks 5-6 |

---

## Security Impact

Implementing these controls prevents:
- Malicious firmware installation
- Downgrade attacks to vulnerable versions
- Firmware tampering during download
- Man-in-the-middle attacks
- Physical tampering exploitation
- Botnet recruitment of devices

Result: OTA update process becomes security feature instead of vulnerability vector
