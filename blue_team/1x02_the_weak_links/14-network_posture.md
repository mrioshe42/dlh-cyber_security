# 14. The Network Posture

### Segmentation Impact Analysis

#### Analysis 1
**CVE:** CVE-2019-9193
**Host:** billing-srv-01
**CVSS Base Score:** 7.2

**Scenario A: Current (flat network):**
*   **Who can reach this vulnerability:** All 10.10.0.0/16 endpoints, including guest Wi-Fi and unmanaged IoT devices.
*   **What the attacker can reach AFTER exploitation:** All systems within the 10.10.0.0/16 subnet, including the EHR database and domain controllers.
*   **Effective Risk:** High. An attacker gains remote code execution on the billing server, which acts as a pivot point for the entire clinical network.

**Scenario B: Hypothetical (segmented network):**
*   **Who can reach this vulnerability:** Only systems within the defined application/billing VLAN.
*   **What the attacker can reach AFTER exploitation:** Only other systems within the same billing VLAN, unless lateral movement is allowed through an explicit firewall rule.
*   **Effective Risk:** Low. The compromise is contained to the billing segment, preventing the attacker from accessing patient records or critical infrastructure.

**Risk Amplification Factor:** High (approx. 5x). The flat network removes all internal barriers, effectively granting the attacker the same level of access as a legitimate administrator upon successful exploit.

#### Analysis 2
**CVE:** CVE-2017-8563
**Host:** DC-01
**CVSS Base Score:** 8.1

**Scenario A: Current (flat network):**
*   **Who can reach this vulnerability:** Every endpoint on the network can communicate directly with the Domain Controller.
*   **What the attacker can reach AFTER exploitation:** The entire Active Directory environment, allowing for domain-wide privilege escalation and full network takeover.
*   **Effective Risk:** Critical. Total loss of identity and access control for the entire facility.

**Scenario B: Hypothetical (segmented network):**
*   **Who can reach this vulnerability:** Only authenticated server subnets (e.g., specific management VLANs).
*   **What the attacker can reach AFTER exploitation:** Restricted to the management segment. The scope for relay attacks is severely limited as the attacker cannot reach the DC from a compromised workstation.
*   **Effective Risk:** Moderate. The domain remains protected from workstations, and the attack surface is significantly reduced.

**Risk Amplification Factor:** Very High (approx. 10x). Flat network "any-to-any" connectivity provides the essential prerequisite for NTLM relay attacks to escalate a single workstation compromise into a domain-wide disaster.

#### Analysis 3
**CVE:** CVE-2022-21663
**Host:** Grafana-srv
**CVSS Base Score:** 7.2

**Scenario A: Current (flat network):**
*   **Who can reach this vulnerability:** Any host on the 10.10.0.0/16 subnet.
*   **What the attacker can reach AFTER exploitation:** The server's OS, sensitive dashboard data, and potentially other internal APIs reachable from this segment.
*   **Effective Risk:** Moderate. A compromised workstation can reach this service, creating a pathway for authentication bypass.

**Scenario B: Hypothetical (segmented network):**
*   **Who can reach this vulnerability:** Only systems in the management/admin VLANs.
*   **What the attacker can reach AFTER exploitation:** Only the local segment; traffic to other segments is blocked by the internal firewall.
*   **Effective Risk:** Low. The breach remains localized to the administrative zone, protecting clinical data segments.

**Risk Amplification Factor:** Moderate (approx. 3x). The flat network transforms a server-side exploit into an accessible lateral movement vector available to every infected workstation in the hospital.

### Network Posture Summary
The aggregate risk amplification effect of the flat network across the entire scan report is that it renders individual vulnerability remediation nearly futile; as long as the network remains flat, an adversary only needs to be "right once" to gain broad access to the entire environment. Patching a single CVE fixes the hole, but it does not remove the adversary’s ability to move through the wall once they find a different gap, whereas segmentation effectively turns the entire building into a series of isolated vaults. Therefore, network segmentation is arguably more impactful than patching; while patching reduces the *number* of entry points, segmentation reduces the *utility* of every single one of them, preventing a minor compromise on a low-value asset from escalating into a full-scale clinical or financial data breach.
