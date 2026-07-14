# 12. STRIDE Across the Architecture

### System: PACS / Medical Imaging

**Architecture Notes**: pacs-srv-01, XP MRI workstation, radiology workstations; relies on flat network and shared legacy credentials.

| STRIDE | Threat | Impact | Severity |
| --- | --- | --- | --- |
| S | Spoofing a radiology workstation to pull unauthorized diagnostic images. | Unauthorized viewing of PHI/images. | High |
| T | Tampering with image metadata to misidentify patient diagnostic results. | Potential misdiagnosis or incorrect treatment. | Critical |
| R | Radiologist denies accessing unauthorized images due to lack of granular auditing. | Inability to prove insider misuse. | Medium |
| I | Information Disclosure of unencrypted images in transit. | Major HIPAA violation; leak of medical history. | High |
| D | Denial of Service via malware on the legacy XP MRI workstation. | Halt of diagnostic imaging services. | High |
| E | Elevation of privilege on XP workstation via local exploit to gain PACS access. | Full unauthorized control of the PACS image repository. | Critical |

**Top Threat**: Tampering (PACS-T) is the most dangerous threat because unauthorized modification of diagnostic metadata or images directly compromises patient safety and can lead to irreversible medical errors.

### System: Active Directory (AD)

**Architecture Notes**: ad-dc-01, ad-dc-02; single point of failure for all identity/authentication; weak policies, no MFA.

| STRIDE | Threat | Impact | Severity |
| --- | --- | --- | --- |
| S | Spoofing a Domain Controller via rogue DC addition. | Total domain compromise. | Critical |
| T | Tampering with group policy objects (GPOs) to deploy malicious software. | Widespread system-wide infection. | Critical |
| R | Repudiation of administrative actions due to log tampering. | Inability to perform incident forensics. | High |
| I | Information Disclosure of Kerberos hashes via DCSync. | Offline cracking of all user credentials. | Critical |
| D | Denial of Service by deleting/corrupting ntds.dit. | Total organizational authentication failure. | Critical |
| E | Elevation of privilege from user to Domain Admin via Kerberoasting. | Full control over entire network environment. | Critical |

**Top Threat**: Information Disclosure (AD-I) via Kerberos hash theft is the most dangerous threat because it allows the attacker to compromise all user credentials, providing persistent, undetectable access across the entire enterprise.

### System: Network Infrastructure

**Architecture Notes**: FortiGate, core switch, Westside router, VPN tunnels; perimeter-focused with no internal segmentation.

| STRIDE | Threat | Impact | Severity |
| --- | --- | --- | --- |
| S | Spoofing VPN traffic to bypass perimeter access controls. | Unauthorized entry into the internal network. | High |
| T | Tampering with core switch VLAN configurations to bypass segmentation. | Exposure of restricted subnets. | High |
| R | Repudiation of malicious traffic logs at the Westside router. | Inability to track the source of an external attack. | Medium |
| I | Information Disclosure of internal network topology via port scanning. | Targeted mapping of high-value internal assets. | Medium |
| D | Denial of Service on the FortiGate gateway via volumetric attack. | Loss of external connectivity and remote access. | High |
| E | Elevation of privilege via FortiGate management interface exploit. | Full control over all network traffic/firewall rules. | Critical |

**Top Threat**: Elevation of Privilege (NET-E) on the FortiGate firewall is the most dangerous threat because it grants the attacker absolute control over the network's traffic flow, allowing them to bypass all remaining security controls.
