# Correlated Incident Timeline: LH-2026-0414-01

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
| --- | --- | --- | --- | --- | --- |
| 2026-04-13T03:10:22Z | ART-005 (AD auth) | dmarsh normal logon to WST-WS-031 (10.42.118.31) | T1078 | confirmed | ad_auth_log.jsonl line 1 |
| 2026-04-13T18:13:44Z | ART-004 (proxy) | dmarsh accesses Outlook mailbox | — | confirmed | proxy_log.jsonl line 13 |
| 2026-04-13T18:14:02Z | ART-004 (proxy) | **Phishing link clicked:** dmarsh visits typosquat domain ms0365-support.login-verification.click | T1598.003 | confirmed | proxy_log.jsonl line 14 |
| 2026-04-13T18:14:07Z | ART-004 (proxy) | Phishing site loads login form (logo + CSS) | T1598.003 | confirmed | proxy_log.jsonl lines 15-16 |
| 2026-04-13T18:14:41Z | ART-004 (proxy) + ART-005 (Azure AD) | **Credentials submitted** to phishing form (POST); simultaneous Azure AD signin from Russia IP 45.63.9.88 | T1110.004 + T1528 | confirmed | proxy_log.jsonl line 20 + ad_auth_log.jsonl line 3 |
| 2026-04-13T18:14:43Z | ART-004 (proxy) | **Malware download:** update.zip (421 KB) from phishing site; file saved to Downloads | T1105 | confirmed | proxy_log.jsonl line 21 |
| 2026-04-13T18:14:43Z | ART-001 (filesystem) | update.zip created in C:\Users\dmarsh\Downloads\ | T1105 | confirmed | filesystem_analysis.md ART-001-F01 |
| 2026-04-13T19:02:11Z | ART-005 (AD auth) | Normal logoff from WST-WS-031 | — | confirmed | ad_auth_log.jsonl line 4 |
| 2026-04-14T02:44:02Z | ART-005 (AD auth) | **Unusual hour logon** to WST-WS-031 at 02:44 UTC (attacker action); note="unusual_hour_for_user" | T1078 | confirmed | ad_auth_log.jsonl line 5 |
| 2026-04-14T02:44:17Z | ART-005 (VPN log) | **VPN logon** using dmarsh credentials from Russia IP 45.63.9.88 | T1078 | confirmed | ad_auth_log.jsonl line 7 |
| 2026-04-14T02:46:41Z | ART-002 (memory) + filesystem | **PowerShell execution** with `-ep bypass -w hidden -enc` (encoded payload) | T1059.001 | confirmed | memory_analysis.md M02 + filesystem_analysis.md ART-001-F03 |
| 2026-04-14T02:46:56Z | ART-001 (filesystem) | **Malicious files staged:** update.xml created in C:\Users\dmarsh\AppData\Local\Temp\ (MSBuild config) | T1105 | confirmed | filesystem_analysis.md ART-001-F02 |
| 2026-04-14T02:46:57Z | ART-002 (memory) + ART-004 (SIEM) | **MSBuild.exe spawned** by PowerShell (PID 8104, parent PID 7812); **C2 beacon starts** to 185.220.101.47:443 | T1127.001 + T1071.001 | confirmed | memory_analysis.md M01 + SIEM alert A-20260414-9841 |
| 2026-04-14T02:47:02Z | ART-004 (proxy) | **First C2 connection:** MSBuild connects to TOR exit relay 185.220.101.47:443 | T1071.001 + T1090.003 | confirmed | proxy_log.jsonl line 24 |
| 2026-04-14T02:47:06Z | ART-001 (filesystem) + ART-001-R04 (registry) | **Persistence installed:** Scheduled task UpdateScheduler created (C:\Windows\System32\Tasks\) | T1053.005 | confirmed | persistence_analysis.md ART-001-R04 |
| 2026-04-14T02:47:09Z | ART-001-R01 (registry) | **Persistence installed:** Run key WindowsUpdateSvc added to HKCU (→ svchost-update.exe) | T1547.001 | confirmed | persistence_analysis.md ART-001-R01 |
| 2026-04-14T02:47:11Z | ART-004 (SIEM) | **SIEM alert fires:** A-20260414-9841 "Suspicious process tree: PowerShell → MSBuild" | T1127.001 | confirmed | SIEM alert A-20260414-9841 |
| 2026-04-14T02:47:11Z | ART-002 (memory) | **Code injection confirmed:** MZ header found in anonymous RWX memory region (0x1f0000) within MSBuild.exe | T1055.001 | confirmed | memory_analysis.md M05 |
| 2026-04-14T03:02:00Z | ART-002 (acquisition) | **Memory capture:** wst-ws-031.mem acquired while C2 connection active; NTLM hashes + Kerberos tickets accessible in LSASS | T1003.001 | confirmed | memory_analysis.md M07 + M08 |
| 2026-04-14T03:22:47Z | ART-005 (AD auth) | **Kerberos TGS-REQ:** Kerberos request for cifs/WST-WS-017 from WST-WS-031 (Pass-the-Ticket attack) | T1558.003 | confirmed | ad_auth_log.jsonl line 8 |
| 2026-04-14T03:23:01Z | ART-005 (AD auth) | **Lateral movement logon:** Network logon to WST-WS-017 using dmarsh Kerberos ticket | T1550.003 | confirmed | ad_auth_log.jsonl line 10 |
| 2026-04-14T03:23:14Z | ART-003 (memory) | **MSBuild.exe spawned** on WST-WS-017 by PowerShell (same attack pattern) | T1127.001 | confirmed | memory_analysis.md M01 (ART-003) |
| 2026-04-14T03:27:13Z | ART-004 (proxy) | **Second C2 connection:** MSBuild on WST-WS-017 connects to different C2 infrastructure 91.234.99.107:443 | T1071.001 | confirmed | proxy_log.jsonl line 26 + memory_analysis.md M02 (ART-003) |
| 2026-04-14T03:40:18Z | ART-005 (AD auth) | **Kerberos TGS-REQ:** Request for cifs/LIS-WSIDE-01 (file server) from WST-WS-017 | T1570 | confirmed | ad_auth_log.jsonl line 11 |
| 2026-04-14T03:42:08Z | ART-005 (AD auth) | **Logon to LIS-WSIDE-01:** Network logon to file server using stolen Kerberos ticket | T1550.003 | confirmed | ad_auth_log.jsonl line 13 |
| 2026-04-14T03:43:30Z | ART-005 (file audit) | **Data exfiltration:** dmarsh account opens 14 PDF files from LIS_REPORTS$ share on LIS-WSIDE-01 (C:\LIS\reports\daily\*.pdf) | T1005 + T1537 | confirmed | ad_auth_log.jsonl line 14 + filesystem_analysis.md ART-001-E06 |
| 2026-04-14T06:14:00Z | ART-001 (acquisition) | **Disk image complete:** wst-ws-031.dd acquired after 143-minute imaging process (04:51Z–06:14Z) | — | confirmed | chain_of_custody.md artifact registry |
| 2026-04-14T07:30:00Z | Legal | **Litigation hold placed:** LH-2026-0414-01 issued by Helena Reyes | — | confirmed | chain_of_custody.md case header |
| 2026-04-14T10:12:00Z | Endpoint | **Source destroyed:** WST-WS-031 rebuilt from baseline image | — | confirmed | chain_of_custody.md access log |
| 2026-04-14T11:04:00Z | Endpoint | **Source destroyed:** WST-WS-017 rebuilt from baseline image | — | confirmed | chain_of_custody.md access log |

## Attack Sequence Summary

**Stage 1: Initial Access (2026-04-13, 8h before execution)**
- Phishing email delivered with typosquat link (ms0365-support.login-verification.click)
- dmarsh clicks link, submits credentials
- Attacker receives credentials, downloads update.zip payload
- Attacker accesses Azure AD from Russia IP (45.63.9.88)

**Stage 2: Execution & C2 Activation (2026-04-14, 02:46Z–02:47Z, 14 minutes)**
- Attacker logs in from Russia via VPN using stolen dmarsh credentials
- PowerShell executes with execution bypass and hidden window
- PowerShell decodes and executes Base64 payload
- MSBuild spawned as child process, loads update.xml inline tasks
- C# code injected into MSBuild memory (MZ header at 0x1f0000)
- Active C2 connection to TOR exit relay (185.220.101.47:443)
- Scheduled tasks and Run keys installed for persistence
- SIEM alert A-20260414-9841 fires 14 seconds after MSBuild execution

**Stage 3: Credential Harvesting & Lateral Movement (2026-04-14, 03:22Z–03:43Z, 21 minutes)**
- Attacker harvests NTLM hashes and Kerberos tickets from LSASS
- Uses Pass-the-Ticket to request TGS for cifs/WST-WS-017
- Lateral movement to WST-WS-017; PowerShell & MSBuild executed (same template)
- Second C2 connection to different infrastructure (91.234.99.107:443)
- Further lateral movement to LIS-WSIDE-01 (file server)
- 14 patient lab report PDFs accessed on shared drive
- Data likely staged for exfiltration

**Key Metrics**
- Dwell time: ~8 hours (phishing to execution)
- C2 active at acquisition: 15+ minutes
- Lateral movement span: 2 hosts (WST-WS-031 → WST-WS-017 → LIS-WSIDE-01)
- Data files accessed: 14 laboratory PDFs (patient/PHI records)
- Persistence mechanisms: 4 (2 Run keys, 2 Scheduled tasks)
