## 3. The 72-Hour Plan

### Tier 1 - Tonight (0–12 Hours)

*Actions taken immediately with zero budget approval, no procurement, and minimal risk of service disruption before logging off.*

* **Action 1:** Temporarily disable the SSL-VPN service on the perimeter FortiGate appliance (or restrict incoming VPN access strictly to pre-approved emergency administrator source IPs via local inbound firewall rules).
* **Phase Blocked:** Phase 1 (Initial Access via CVE-2023-27997)
* **Owner:** Sarah Park
* **Prerequisites:** None
* **Risk of Action:** Remote clinical staff or off-hours on-call physicians may temporarily lose remote VPN access until whitelist rules or alternative paths are set.
* **Risk of Inaction:** Attackers execute unauthenticated remote code execution via CVE-2023-27997 to establish an immediate bridgehead on the network perimeter.

* **Action 2:** Physically disconnect the primary backup Network-Attached Storage (NAS) array (`NAS-01`) from the active network switch ports.
* **Phase Blocked:** Phase 7 (Impact / Ransomware Deployment & Backup Encryption)
* **Owner:** IT Staff Member 1
* **Prerequisites:** Locate physical hardware in the server room.
* **Risk of Action:** Scheduled overnight incremental backups will fail or error out.
* **Risk of Inaction:** Ransomware lateral movement propagates directly to on-site backup shares, encrypting restore points and forcing complete extortion leverage.

* **Action 3:** Enforce immediate local account lockout policies and audit active Domain Admin group memberships for unauthorized accounts.
* **Phase Blocked:** Phase 2 & 3 (Execution, Persistence, and Privilege Escalation)
* **Owner:** IT Staff Member 2
* **Prerequisites:** Active Directory access.
* **Risk of Action:** Minimal; standard administrative hygiene.
* **Risk of Inaction:** Dormant or recently compromised shadow accounts retain high privileges to move laterally undetected.

### Tier 2 - Tomorrow (12–36 Hours)

*Actions requiring coordination, brief operational service windows, and emergency executive/board sign-off.*

* **Action 1:** Secure emergency executive approval to fund the Fortinet support contract renewal ($2,400) and download/apply the latest stable firmware patch for CVE-2023-27997.
* **Phase Blocked:** Phase 1 (Initial Access)
* **Owner:** You (CISO) & Sarah Park
* **Prerequisites:** Emergency Board budget authorization.
* **Risk of Action:** Brief perimeter internet/VPN drop during the reboot cycle required post-patch application.
* **Risk of Inaction:** The firewall remains vulnerable to pre-authentication remote code execution, rendering temporary workarounds permanent and brittle.

* **Action 2:** Deploy emergency host-based isolation policies via Sophos Intercept X to lock down outbound communications from legacy systems (such as the Windows XP MRI workstation).
* **Phase Blocked:** Phase 5 (Lateral Movement)
* **Owner:** Sarah Park & IT Staff Member 1
* **Prerequisites:** Sophos console access.
* **Risk of Action:** Potential interference with legacy vendor software communication if misconfigured.
* **Risk of Inaction:** Legacy systems remain open pivot points for automated worm-like lateral movement.

* **Action 3:** Revoke all active user session tokens across Microsoft 365 and force a global password reset paired with temporary MFA token re-registration.
* **Phase Blocked:** Phase 2 & 4 (Persistence and Defense Evasion)
* **Owner:** IT Staff Member 2
* **Prerequisites:** M365 Global Admin credentials.
* **Risk of Action:** User friction and temporary helpdesk ticket surges as clinical staff re-authenticate.
* **Risk of Inaction:** Existing session hijack tokens or compromised credentials persist indefinitely, bypassing perimeter defenses.

### Tier 3 - This Week (36–72 Hours)

*Actions requiring vendor coordination, multi-day configuration changes, or structured deployment testing.*

* **Action 1:** Procure and deploy a dedicated enterprise firewall at the Westside Clinic to replace the unmanaged consumer routing equipment.
* **Phase Blocked:** Phase 5 (Lateral Movement from Remote Sites)
* **Owner:** External Vendor & Sarah Park
* **Prerequisites:** Procurement processing ($4,000 budget allocation from Strategy Control 6).
* **Risk of Action:** Misconfiguration of site-to-site tunnels interrupting remote clinic billing operations.
* **Risk of Inaction:** Westside Clinic remains an unmonitored backdoor into the central database environment.

* **Action 2:** Implement core switch VLAN segmentation configurations (802.1Q) to isolate medical IoT infusion pumps and clinical databases into separate micro-zones.
* **Phase Blocked:** Phase 5 (Lateral Movement across Flat Network)
* **Owner:** Sarah Park & IT Staff Member 1 & 2
* **Prerequisites:** Completed switch configuration templates and change control approval.
* **Risk of Action:** Inter-VLAN routing rule errors could disrupt EHR application traffic between workstations and database servers.
* **Risk of Inaction:** The flat internal network architecture allows rapid, unimpeded ransomware propagation to core clinical assets.

* **Action 3:** Establish an out-of-band, immutable cloud backup vault (AWS S3 Glacier Object Lock) and complete a test recovery run.
* **Phase Blocked:** Phase 7 (Impact / Extortion)
* **Owner:** Sarah Park
* **Prerequisites:** AWS account setup and storage allocation ($15,000 budget from Strategy Control 4).
* **Risk of Action:** Initial sync bandwidth bottlenecks over standard clinical internet connections.
* **Risk of Inaction:** Complete reliance on local, vulnerable backups leaves MedDefense defenseless against total operational lockout.

### Resource Conflict Assessment

* **Identified Conflicts:**
1. *Personnel Bottleneck:* Sarah Park is required as the technical lead for both Tier 1 (FortiGate VPN restriction tonight) and Tier 2/3 (firewall firmware patching, switch VLAN configuration, and EDR deployment). She cannot execute all configuration changes simultaneously with only 2 available IT staff.
2. *System Availability Conflict:* Core networking changes (VLAN segmentation) and firewall patching both require maintenance windows that overlap with active clinical shift rotations.


* **Conflict Resolution:**
* **Delegation of Routine Tasks:** Offload manual tasks (such as physical NAS cable disconnection and user session token revocation) to the 2 supporting IT staff under Sarah's remote direction, freeing Sarah to focus exclusively on high-risk edge firewall controls.
* **Phased Maintenance Scheduling:** Defer the disruptive internal switch VLAN recabling (Tier 3) to a scheduled 2:00 AM low-census clinical window, while executing zero-disruption perimeter controls (VPN lockdown and backup isolation) immediately tonight.
