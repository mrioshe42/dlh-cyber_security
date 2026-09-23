# Network Forensics Investigation Report

## Executive Summary
A coordinated cyber attack against MedDefense Health Systems occurred between April 14 and April 15, 2026, initiated by a targeted phishing campaign and culminating in internal network compromise and data exfiltration. The attacker successfully harvested user credentials via a rogue login portal, established command-and-control beaconing, pivoted into the internal network through an unauthorized external VPN session, and exfiltrated structured records using covert DNS tunneling. While core clinical databases and restricted internal endpoints successfully resisted lateral movement, the intrusion compromised operational servers and leaked sensitive information.

## Investigation Scope
* **Analyzed PCAP Files:** `normal_baseline_clinical.pcap`, `phishing_click.pcap`, `c2_beaconing.pcap`, `dns_exfil.pcap`, `lateral_movement.pcap`, `full_timeline.pcap`
* **Time Period Covered:** April 14, 2026 (06:00) through April 15, 2026 (22:45)
* **Tools Used:** `tshark`, `tcpdump`, custom Bash automation scripts, standard text utilities
* **Evidence Sources Not Used:** SIEM dashboards, Endpoint Detection and Response (EDR) agent logs, physical device memory dumps, mail server gateway logs

## Methodology
The investigation followed a rigorous forensic methodology based entirely on packet-level evidence:
1. **Baseline Establishment:** Mapped normal clinical traffic from `normal_baseline_clinical.pcap` to understand standard protocol distributions, DNS rates, and connection rhythms.
2. **Known-IOC Search:** Correlated packet captures against indicators identified during the 4x00 phase (`meddefense-portal.com`, `91.234.99.107`).
3. **DNS Analysis:** Inspected query types, domain label entropies, and response sizes to detect covert channeling.
4. **TLS Metadata Analysis:** Parsed Server Name Indication (SNI) values, cipher suites, and certificate details without decrypting session payloads.
5. **Timing Analysis:** Measured inter-arrival times (IAT) and connection intervals to expose automated C2 beaconing.
6. **Cross-PCAP Correlation:** Unified disparate packet captures into a chronologically coherent master timeline.

## Findings by Attack Phase

### Phase 1: Initial Access (Spearphishing Link)
* **Narrative:** An email containing a malicious link was delivered to a clinical user.
* **Evidence Citation:** 4x00 email evidence, Email 2 (2026-04-14 14:47)
* **MITRE ATT&CK:** T1566.002 (Spearphishing Link)
* **Confidence Level:** Contextual (Supported by 4x00 findings)
* **What PCAP Proves:** Direct packet capture for this delivery phase is absent; established via prior email analysis.

### Phase 2: Credential Harvesting Session
* **Narrative:** A nurse workstation resolved the phishing domain and engaged in an encrypted TLS session submitting form data.
* **Evidence Citation:** `phishing_click.pcap`, 2026-04-14 15:02:33 to 15:03:20
* **MITRE ATT&CK:** T1056.003 (Web Portal Capture)
* **Confidence Level:** High (Strong Inference)
* **What PCAP Proves:** DNS resolution to `91.234.99.107` and a 487-byte client TLS record consistent with credential form submission.

### Phase 3: Command and Control Beaconing
* **Narrative:** The compromised workstation initiated automated, periodic HTTPS connections to the phishing infrastructure.
* **Evidence Citation:** `c2_beaconing.pcap`, 2026-04-15 02:00 to 03:55
* **MITRE ATT&CK:** T1071.001 (Web Protocols)
* **Confidence Level:** Confirmed
* **What PCAP Proves:** 24 sessions occurring at rigid ~300-second intervals with minimal jitter.

### Phase 4: External Access / VPN Pivot
* **Narrative:** An external IP address authenticated to the organization's VPN endpoint using the harvested credentials.
* **Evidence Citation:** `full_timeline.pcap`, 2026-04-15 13:45:22 (Source: `154.118.42.89`)
* **MITRE ATT&CK:** T1133 (External Remote Services)
* **Confidence Level:** High (Strong Inference)
* **What PCAP Proves:** SSL-VPN session establishment originating from Lagos, Nigeria, preceding lateral movement by 45 minutes.

### Phase 5: Lateral Movement
* **Narrative:** The attacker used the compromised domain account (`dmarsh`) to initiate an RDP session from the clinical workstation to the internal billing server.
* **Evidence Citation:** `lateral_movement.pcap`, 2026-04-15 14:30:12
* **MITRE ATT&CK:** T1021.001 (Remote Desktop Protocol)
* **Confidence Level:** Confirmed
* **What PCAP Proves:** Successful cross-subnet RDP authentication session between `10.10.2.15` and `10.10.1.10`.

### Phase 6: Discovery
* **Narrative:** From the billing server, the attacker enumerated network shares and performed directory listings.
* **Evidence Citation:** `lateral_movement.pcap`, 2026-04-15 14:35 to 14:42
* **MITRE ATT&CK:** T1135 (Network Share Discovery), T1083 (File and Directory Discovery)
* **Confidence Level:** Confirmed
* **What PCAP Proves:** SMB session setups, directory listings (23 entries enumerated on `NAS-01`), alongside TCP resets/access denials on restricted internal targets.

### Phase 7: Exfiltration
* **Narrative:** Data was compressed or encoded and exfiltrated from the environment using DNS TXT record queries.
* **Evidence Citation:** `dns_exfil.pcap`, 2026-04-15 22:15 to 22:45
* **MITRE ATT&CK:** T1048.003 (Exfiltration Over Alternative Protocol)
* **Confidence Level:** Confirmed
* **What PCAP Proves:** 120 anomalous TXT queries directed to `data-sync.meddefense-portal.com` featuring 44-60 character high-entropy subdomains.


## Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
| :--- | :--- | :--- | :--- | :--- |
| Domain | `meddefense-portal.com` | 4x00 / PCAP 1 | High | Blocklist / DNS Monitoring |
| IP Address | `91.234.99.107` | 4x00 / PCAP 1 & 3 | High | Firewall / Perimeter Blocking |
| Domain | `data-sync.meddefense-portal.com` | PCAP 4 | High | DNS Tunneling Rule Trigger |
| IP Address | `154.118.42.89` | PCAP 5 | High | Geo-IP / VPN Access Control |
| Account | `dmarsh` | PCAP 4 & 5 | High | UEBA / Credential Monitoring |

## Impact Assessment
* **Data Likely Exfiltrated:** Structured clinical/billing records encoded over the DNS TXT tunneling channel (~4-5 KB raw estimate).
* **Systems Involved:** WS-NURSE-04 (`10.10.2.15`), VPN Gateway (`10.10.0.1`), billing-srv-01 (`10.10.1.10`), NAS-01 (`10.10.1.60`).
* **Systems Protected / Not Reached:** Restricted internal servers (`10.10.4.100`, `10.10.4.101`) successfully returned TCP resets and refused unauthorized SMB connections.
* **Credential Exposure:** Domain account `dmarsh` compromised and actively leveraged for external VPN access and internal RDP pivoting.
* **Regulatory & Business Concerns:** Potential HIPAA exposure due to unauthorized billing backup discovery and data exfiltration from healthcare systems.

## Detection Gap Analysis
* **What Packet Evidence Revealed:** Full visibility into wire-level communications, connection intervals, DNS query structures, and protocol handshakes.
* **What Could Have Detected Activity Earlier:** Automated EDR telemetry, anomaly-based SIEM alerts on outbound HTTP beaconing, and automated DNS length monitoring.
* **Behavioral Detection Gaps:** Lack of baseline behavioral analysis allowed periodic C2 beaconing to bypass standard signature-based IDSs.
* **DNS Tunneling Detection Gap:** Absence of volume-based or label-length alerts on DNS TXT queries permitted covert exfiltration.
* **VPN Anomaly Detection Gap:** Geographically impossible login velocity (VPN session originating from Nigeria for a local clinical account) went unflagged.
* **Lateral Movement Detection Gap:** Cross-role RDP usage (clinical workstation accessing server VLAN) was not restricted or alerted.

## Detection Rules Recommended
1. **C2 Beaconing Detection:** Alert when an internal host connects to a single external destination > 10 times in 60 minutes with low interval standard deviation.
2. **DNS Query Length Anomaly:** Alert when left-most DNS labels exceed 40 characters in conjunction with TXT query types.
3. **VPN Geo-Anomaly:** Alert when a user account initiates a VPN session from an unfamiliar country or high-risk ASN.
4. **Cross-Role RDP:** Alert when accounts associated with clinical roles initiate RDP sessions into server subnets.
5. **Campaign Lookalike Domain Alert:** Alert on TLS SNI or DNS requests matching known phishing patterns or newly observed domain structures.

## Recommendations

### Immediate (Next 24 Hours)
* Isolate involved clinical workstations and server nodes (`WS-NURSE-04`, `billing-srv-01`).
* Force an immediate password reset and session invalidation for user account `dmarsh`.
* Implement perimeter firewall blocks for `91.234.99.107` and `*.meddefense-portal.com`.
* Preserve all current packet captures and volatile system evidence.

### Short-Term (Next 7 Days)
* Deploy behavioral C2 beaconing detection logic across network monitoring tools.
* Review and tighten VPN access control lists, implementing mandatory multi-factor authentication (MFA) and geo-restrictions.
* Enhance DNS egress monitoring to flag high-frequency TXT queries and long subdomain strings.
* Scan the environment for additional compromised accounts or persistence mechanisms.

### Medium-Term (Next 30 Days)
* Enforce stricter email gateway authentication policies (SPF, DKIM, DMARC).
* Implement network segmentation controls restricting RDP traffic between user VLANs and server VLANs.
* Conduct a comprehensive healthcare data exposure and access audit.

## Evidence Chain

| PCAP Filename | Purpose | Capture Time Window | Handling Notes |
| :--- | :--- | :--- | :--- |
| `normal_baseline_clinical.pcap` | Establish clinical traffic baseline | Apr 14, 2026 (06:00 - 06:30) | Stored on secure IR shared drive |
| `phishing_click.pcap` | Capture exact phishing click event | Apr 14, 2026 (15:02 - 15:03) | Integrity verified via SHA-256 |
| `c2_beaconing.pcap` | Detect outbound C2 beaconing | Apr 15, 2026 (02:00 - 04:00) | Isolated for forensic replay |
| `dns_exfil.pcap` | Analyze DNS tunneling exfiltration | Apr 15, 2026 (22:15 - 22:45) | Filtered for billing subnet |
| `lateral_movement.pcap` | Trace cross-subnet RDP/SMB pivots | Apr 15, 2026 (14:30 - 14:45) | Sanitized for analyst review |
| `full_timeline.pcap` | End-to-end incident reconstruction | Apr 14-15, 2026 (Full Window) | Master composite archive |

## Continuity with 4x00
This network forensics investigation updates and strengthens the previous 4x00 findings in several vital ways:
* **Credential Exposure:** Moves from a theoretical likelihood to strongly supported fact based on subsequent VPN login metadata and internal RDP activity.
* **Network Timeline:** Fills the critical gap between initial email delivery and internal server discovery with exact packet timestamps.
* **Infrastructure Association:** Links the phishing email domains directly to post-click C2 beaconing and DNS exfiltration channels.
* **Impact Expansion:** Confirms that the compromise extended beyond email into active internal lateral movement and covert data exfiltration.
