# 5. The Supply Chain Question

## Critical Vendor Risk Analysis

**1. MedTech Solutions**
*   **Service:** EHR maintenance provider (Annual contract: $145,000; 4hr SLA).
*   **Access Type:** Network/Application.
*   **Access Scope:** Direct administrative access to the `ehr-srv-01` server and the primary EHR database.
*   **Compromise Scenario:** Threat actors compromise MedTech’s VPN credentials through phishing, allowing them to tunnel into our environment, exploit the RDP service on `ehr-srv-01`, and exfiltrate 50,000 patient records directly from the database.
*   **Existing Controls:** Reference 1x00 Control Matrix (Net-04: Network Segmentation; IAM-02: VPN MFA).
*   **Risk Assessment:** **Critical**. This is the highest risk due to the direct, unmediated path to our most sensitive data repository and the reliance on vendor-managed credentials.

**2. Microsoft**
*   **Service:** O365 E3 (Email, SharePoint, OneDrive).
*   **Access Type:** Application/Cloud.
*   **Access Scope:** Full access to all organizational communications, internal policy documents, and Entra ID (Identity Management).
*   **Compromise Scenario:** Compromise of Microsoft’s infrastructure or an internal MedDefense tenant configuration error allows attackers to perform Business Email Compromise (BEC) and intercept sensitive administrative credentials.
*   **Existing Controls:** Reference 1x00 Control Matrix (IAM-02: Enforced Multi-Factor Authentication; SEC-01: Conditional Access Policies).
*   **Risk Assessment:** **High**. While robust, the centralization of our entire identity and communication stack makes this a high-value target for lateral movement.

**3. Sophos**
*   **Service:** Endpoint Protection.
*   **Access Type:** Application (Agent-based).
*   **Access Scope:** Full control over all managed endpoints and the ability to push policy/update configurations.
*   **Compromise Scenario:** A supply chain attack targeting Sophos’s update infrastructure pushes malicious signed binaries to our entire endpoint fleet, bypassing traditional perimeter defenses.
*   **Existing Controls:** Reference 1x00 Control Matrix (Sys-03: Restricted Software Update Windows).
*   **Risk Assessment:** **High**. The ubiquity of the agent across all internal assets makes this a "master key" if the vendor's distribution mechanism is breached.

**4. Siemens**
*   **Service:** MRI scanner manufacturer maintenance.
*   **Access Type:** Physical/Network.
*   **Access Scope:** Remote maintenance of the legacy Windows XP workstation controlling the MRI scanner.
*   **Compromise Scenario:** Attackers exploit unpatched vulnerabilities in the legacy Windows XP OS via Siemens’ remote portal; they then move laterally to the medical imaging subnet to disrupt clinical operations.
*   **Existing Controls:** Reference 1x00 Control Matrix (Net-05: Air-gapped network segments).
*   **Risk Assessment:** **Medium**. The risk is mitigated by the isolation of the medical imaging subnet, though the legacy OS remains a significant vulnerability.

**5. Greenfield Building Management**
*   **Service:** HQ office building network/physical infrastructure.
*   **Access Type:** Physical/Network.
*   **Access Scope:** Manages core switches and infrastructure supporting MedDefense VLANs.
*   **Compromise Scenario:** Compromise of the building management system allows attackers to intercept inter-VLAN traffic or physically gain access to the MDF/IDF closets to tap the network.
*   **Existing Controls:** Reference 1x00 Control Matrix (Net-06: Encrypted traffic tunneling).
*   **Risk Assessment:** **Medium**. Primarily an infrastructure risk; there is no direct access to MedDefense data, but connectivity is a dependency.

## Supply Chain Risk Summary

A compromise of **MedTech Solutions** would cause the most damage to MedDefense because they hold direct, administrative-level access to the EHR database. Given our patient records are our most sensitive asset, an attacker with MedTech’s privileges could perform a massive data exfiltration event that would trigger severe regulatory fines, patient trust erosion, and litigation. To mitigate this and reduce overall supply chain risk, MedDefense should immediately implement **Zero Trust Network Access (ZTNA)**. By moving away from static VPN tunnels to a granular, identity-aware, and Just-In-Time (JIT) access model, we ensure that vendors like MedTech only have authorized access to specific systems at specific times, thereby eliminating the persistent, high-privilege pathways that currently exist.
