# 13. The ATT&CK Mapping

### Scenario Alpha: "Operation Flatline"

| Step | Tactic | Technique | MedDefense Factor |
| --- | --- | --- | --- |
| 1 | Reconnaissance | Active Scanning: Internet Scanning (T1595.001) | Exposure of FortiGate management interfaces to the internet. |
| 2 | Initial Access | Phishing: Spearphishing Attachment (T1566.001) | Lack of robust email filtering/user awareness for phishing. |
| 3 | Persistence | Create or Modify System Process: Scheduled Task/Job (T1053.005) | Excessive local admin privileges on workstations. |
| 4 | Discovery | Network Service Discovery (T1046) | Flat network architecture (Net-04) allows wide visibility. |
| 5 | Credential Access | OS Credential Dumping: LSASS Memory (T1003.001) | Cached domain credentials stored on end-user machines. |
| 6 | Privilege Escalation | Steal or Forge Authentication Certificates: Pass-the-Hash (T1550.002) | Lack of segmentation between workstations and domain controllers. |
| 7 | Exfiltration | Exfiltration Over C2 Channel (T1041) | No egress filtering; flat network allows direct database access. |
| 8 | Impact | Inhibit System Recovery (T1490) | No offline/immutable backups; excessive permissions on NAS. |
| 9 | Impact | Data Encrypted for Impact (T1486) | Permissive GPO allows deployment to all systems. |


### Scenario Beta: "The Quiet Departure"

| Step | Tactic | Technique | MedDefense Factor |
| --- | --- | --- | --- |
| 1 | Reconnaissance | Internal Spearphishing (T1592) / General Info Gathering | Insecure offboarding process and broad system access. |
| 2 | Discovery | File and Directory Discovery (T1083) | Over-privileged access (read-only) to EHR records. |
| 3 | Collection | Data from Information Repositories (T1213) | Lack of rate-limiting or auditing on record exports. |
| 4 | Exfiltration | Exfiltration Over Physical Medium (T1052.001) | No endpoint security policy restricting USB usage. |
| 5 | Defense Evasion | Indicator Removal on Host (T1070) | Lack of centralized, proactive log monitoring/analysis. |
| 6 | Credential Access | Unsecured Credentials: Credentials in Files (T1552.001) | Sensitive credentials stored in plain-text config files. |
| 7 | Persistence | Valid Accounts (T1078) | Significant latency in IT offboarding workflows. |
| 8 | Exfiltration | Exfiltration Over Alternative Protocol (T1048) | VPN credentials remained active after termination. |


### ATT&CK Coverage Assessment

Looking at both scenarios, **Discovery**, **Credential Access**, and **Exfiltration** are the shared tactical pillars. Both external attackers and malicious insiders leverage the environment's lack of segmentation and visibility—specifically, the ability to freely roam the network (Discovery), harvest credentials (Credential Access), and move data out without friction (Exfiltration). This overlap indicates that MedDefense's most urgent need is not just a single tool, but a foundational shift toward **Zero Trust** principles: implementing network segmentation to prevent lateral discovery, deploying robust Identity and Access Management (IAM) to prevent credential theft and ensure timely offboarding, and establishing centralized logging with real-time alerting (SIEM) to detect unusual data volumes and unauthorized access before exfiltration occurs.
