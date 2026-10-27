# Forensic Findings: IR-2026-0420-01

## Evidence Verification
**ART-001 (cs-ws-101.mem):**  Hash verified; chain of custody intact.

## Key Findings

| Artifact | Finding | Conclusion | Technique | Certainty |
|----------|---------|-----------|-----------|-----------|
| **Memory** | Beacon process tree: WINWORD→PowerShell→svchost32.exe (PID 7318, spawn 14:23:02Z) | Macro execution → PowerShell loader → CS beacon (false svchost naming) | T1566.001, T1059.001, T1036.005 | Confirmed |
| **Memory** | Active TCP connection: svchost32.exe:49871 → 45.152.66.114:443 (ESTABLISHED) | Live C2 beacon to Cobalt Strike team server (VT: 22/91 detections) | T1071.001 | Confirmed |
| **Memory** | Injected memory region in svchost32.exe (entropy 7.8, private+exec+writable) | Encrypted payload staging area; consistent with in-memory C2 | T1140 | Probable |
| **Memory** | Open handle: svchost32.exe → lsass.exe (access 0x1010, READ+QUERY) | Credential dumping via lsass.exe memory read; aligns Sysmon event 10 @ 14:25:02Z | T1110.004 | Confirmed |
| **Disk** | Invoice_Q4_2025.docm (C:\Users\jdoe\Desktop) | Phishing attachment; macro-enabled Word document | T1566.001 | Confirmed |
| **Disk** | inv_payload.ps1 (extracted from memory/disk) | PowerShell downloader: `(New-Object Net.WebClient).DownloadFile()` to C:\ProgramData\Microsoft\svchost32.exe | T1105 | Confirmed |
| **Disk** | svchost32.exe (C:\ProgramData\Microsoft\, unsigned x86-64 PE) | Cobalt Strike beacon binary (MD5: ff4c8a2d…); matches Sysmon event hash @ 14:23:14Z | T1059.001 | Confirmed |
| **Disk** | encryption_staging.ps1 (1,247 lines, dropped 14:23:18Z) | Ransomware script with encryption + file enumeration functions; **NOT EXECUTED** at incident time | T1486 | Confirmed |
| **Proxy** | Phishing: jdoe downloads Invoice_Q4_2025.docm via outlook.office.com @ 14:18:02Z | Email-delivered macro malware | T1566.001 | Confirmed |
| **Proxy** | Payload: inv_payload.ps1 downloaded @ 14:22:19Z from staging.office365-cdn.net (suspicious reputation) | PowerShell downloader fetched by WINWORD macro | T1105 | Confirmed |
| **Proxy** | C2 initiation: svchost32.exe → 45.152.66.114:443 @ 14:23:07Z (jitter 60±10s) | First beacon observed 44s after payload download | T1071.001 | Confirmed |
| **Proxy** | FILE-SVR-01 exfiltration: 2.4 MB egress → 45.152.66.114 @ 02:14:22Z | Large data staging; occurs 21s after lateral movement logon | T1041 | Confirmed |
| **Sysmon** | Service installation: `sc create WinHealthSvc` on CS-WS-104/107/112 (00:04–18Z, parent services.exe) | Persistence via Windows service; fired SIEM alert wz-edr-200214 | T1543.003 | Confirmed |
| **Sysmon** | Ransomware staging: encryption_staging.ps1 dropped on all 4 WS within 3-min window (14:23–26Z) | Synchronized prep for ransomware execution; execution blocked by containment @ 20:45Z | T1486 | Probable |
| **File SVR** | Lateral movement logon: jdoe @ 02:14:00Z via Kerberos from CS-WS-101 (logon_id 0xAF12C4B8) | Pass-the-Ticket: stolen Kerberos keys replayed for file server access | T1550.003 | Confirmed |
| **File SVR** | PHI Access: 1,847 file reads (02:14–41Z, 27 min) via svchost32.exe (shares: \\clinical\\labs, \\clinical\\notes) | Unauthorized access: lab results, ER admission notes, clinical progress notes. jdoe role (scheduler) has no legitimate access. | T1213.002 | Confirmed |
| **File SVR** | Session logoff: jdoe @ 02:41:18Z (same logon_id 0xAF12C4B8) | Session terminated post-exfiltration; mission complete or defensive trigger | — | Confirmed |

## Attack Chain (72-Hour Timeline)

| Stage | Time | Technique | Hosts | Status |
|-------|------|-----------|-------|--------|
| Phishing delivery | 2026-04-17T14:17–18Z | T1566.001 | CS-WS-101 | Confirmed |
| Macro execution | 2026-04-17T14:22Z | T1059.005 | CS-WS-101 | Confirmed |
| PowerShell downloader | 2026-04-17T14:22–23Z | T1059.001, T1105 | CS-WS-101 | Confirmed |
| Beacon execution (svchost32.exe) | 2026-04-17T14:23Z | T1036.005, T1071.001 | CS-WS-101 | Confirmed |
| Credential dumping (lsass) | 2026-04-17T14:25Z | T1110.004 | CS-WS-101 | Confirmed |
| Lateral movement (Pass-the-Ticket) | 2026-04-19T00:04–18Z | T1550.003 | CS-WS-104/107/112 | Confirmed |
| Service persistence | 2026-04-19T00:04–18Z | T1543.003 | CS-WS-104/107/112 | Confirmed |
| FILE-SVR-01 compromise (Kerberos) | 2026-04-19T02:14Z | T1550.003 | FILE-SVR-01 | Confirmed |
| **PHI exfiltration (1,847 records)** | 2026-04-19T02:14–41Z | T1041, T1213.002 | FILE-SVR-01 | **Confirmed** |
| **Ransomware staging (all WS)** | 2026-04-20T14:23–26Z | T1486 | All WS | **Staged NOT executed** |
| **Containment (isolation)** | 2026-04-20T20:35Z | — | All hosts | C2 severed |

**Total Dwell:** 3d 6h 18m (Apr 17 14:17Z → Apr 20 20:35Z)

## HIPAA Breach Status

- **Confirmed Exposure:** 1,847 patient clinical records (lab results, ER notes, progress notes) exfiltrated via FILE-SVR-01 (02:14–41Z, 2026-04-19)
- **Affected Patients:** ~180–300 unique identities (from file date clustering 2026-04-15 to 2026-04-18)
- **Notification Required:** **YES** — Unauthorized access + C2 exfiltration to attacker IP 45.152.66.114
- **Action:** Legal liaison to initiate HIPAA breach notification (individuals, HHS, media if >500 patients)
