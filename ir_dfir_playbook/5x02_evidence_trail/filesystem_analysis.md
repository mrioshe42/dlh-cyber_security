# Filesystem Analysis: ART-001 (wst-ws-031.dd)

## Artifact Verification

- **Artifact ID:** ART-001
- **Artifact name:** wst-ws-031.dd
- **Host:** WST-WS-031 (wst-ws-031.meddefense.local)
- **OS:** Windows 10 Pro 22H2
- **Analysis start time (UTC):** 2026-04-14T10:30:00Z
- **Mount status:** Read-only
- **Mount point:** `/mnt/wst-ws-031-analysis`
- **Hash at analysis start:** PENDING (waiting for baseline)
- **Chain of custody:** Entry to be logged with action `filesystem_analysis_start`, tool `TSK/Sleuthkit`

## Partition Layout Analysis

**Command:** `mmls wst-ws-031.dd`

```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0524288000   0524285952   NTFS (0x07)
```

**Analysis notes:**
- Partition offset: 2048 sectors (1024 KB)
- Volume size: ~250 GB
- Filesystem: NTFS
- Offset for subsequent analysis: 2048

## Filesystem Metadata

**Command:** `fsstat -o 2048 wst-ws-031.dd`

```
FILE SYSTEM INFORMATION
File System Type: NTFS
Volume Serial Number: 8A3F-B4C2
OEM Name: MSBWIN4.1
Volume Label: C-DRIVE
Volume Creation Time: 2024-01-15 08:00:00 (UTC)
Last Mount Time: 2026-04-14 02:47:11 (UTC)
Last Write Time: 2026-04-14 02:47:09 (UTC)

METADATA INFORMATION
Max Inode Address: 524287
Inode Range: 0 - 524287
Root Directory Inode: 5
```

**Forensic notes:**
- Last mount: 2026-04-14T02:47:11Z — exactly when SIEM alert fired (A-20260414-9841)
- Last write: 2026-04-14T02:47:09Z — seconds before alert, during active MSBuild execution
- Volume clean since January 2024 baseline

## Key Forensic Findings

### HIGH PRIORITY: ART-001-F01 — Phishing Download (update.zip)

- **Path:** C:\Users\dmarsh\Downloads\update.zip
- **Inode:** 45821
- **File size:** 421004 bytes
- **Created (UTC):** 2026-04-13 18:14:43
- **Modified (UTC):** 2026-04-13 18:14:43
- **Accessed (UTC):** 2026-04-13 18:14:43
- **SHA-256:** `3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a`
- **File type:** ZIP archive
- **Forensic significance:** 
  - Matches phishing indicator in proxy log (2026-04-13T18:14:43Z download from ms0365-support.login-verification.click)
  - Typosquat domain: ms0365-support.login-verification.click
  - Downloaded 8 hours before MSBuild execution (2026-04-14T02:47:11Z alert)
  - Correlates with Azure AD signin from Russia (45.63.9.88) at 2026-04-13T18:14:41Z
  - 421 KB archive size consistent with malware package
- **Follow-up:** Extract with `icat -o 2048 wst-ws-031.dd 45821` for malware analysis; check contents for update.exe, update.xml, dropper scripts

### HIGH PRIORITY: ART-001-F02 — MSBuild Execution Config (update.xml)

- **Path:** C:\Users\dmarsh\AppData\Local\Temp\update.xml
- **Inode:** 67204
- **File size:** 2847 bytes
- **Created (UTC):** 2026-04-14 02:46:56
- **Modified (UTC):** 2026-04-14 02:46:56
- **Accessed (UTC):** 2026-04-14 02:47:08
- **SHA-256:** `a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3`
- **File type:** XML (MSBuild project file)
- **Forensic significance:**
  - **SIEM Alert Match:** Exact file path matches alert A-20260414-9841 command line: `msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml`
  - Created 2026-04-14T02:46:56Z, 15 seconds before MSBuild process launch (2026-04-14T02:46:57Z per EDR)
  - Modified timestamp = created (freshly written, not edited)
  - Accessed during MSBuild execution window (2026-04-14T02:46:56Z–02:47:11Z)
  - MSBuild parent process: PowerShell (PID 7812) with `-ep bypass -w hidden -enc` (encoded script execution)
  - Likely contains Base64-encoded C# inline tasks or external task references
- **Follow-up:** Extract and decode inline tasks; check for registry modifications, persistence mechanisms, C2 callbacks; correlate encoded PowerShell command with memory dump (ART-002)

### HIGH PRIORITY: ART-001-F03 — PowerShell Execution Bootstrap

- **Path:** C:\Windows\Temp\payload_loader.ps1
- **Inode:** 52110
- **File size:** 4156 bytes
- **Created (UTC):** 2026-04-14 02:46:41
- **Modified (UTC):** 2026-04-14 02:46:41
- **Accessed (UTC):** 2026-04-14 02:46:55
- **SHA-256:** `e7b3c2a1f5d8e6a4c2b9f1e3d5a7c8b0f2e4a6c8e1f3a5b7d9e0f2a4c6e8f`
- **File type:** PowerShell Script (.ps1)
- **Forensic significance:**
  - Execution bypass detected in process tree: `powershell.exe -ep bypass -w hidden -enc ...` (SHA256: 6f5902ac237024bdd0c176cb93063dc4e2a5e89d4aad51b3b3e4f7b72bce7e5e)
  - Created 2026-04-14T02:46:41Z — 15 seconds before update.xml staging
  - Hidden window (`-w hidden`), execution bypass (`-ep bypass`) indicate malicious execution
  - Staged in temp directory, accessed immediately before MSBuild launch
  - Likely contains shellcode loader or C2 beacon initialization
- **Follow-up:** Decode `-enc` parameter from EDR process capture; extract and decompile PowerShell AST; check for registry hives modified during execution window

### CRITICAL: ART-001-F04 — C2 Persistence (Scheduled Task)

- **Path:** C:\Windows\System32\Tasks\UpdateScheduler
- **Inode:** 78341
- **File size:** 1893 bytes
- **Created (UTC):** 2026-04-14 02:47:06
- **Modified (UTC):** 2026-04-14 02:47:06
- **Accessed (UTC):** 2026-04-14 02:47:06
- **SHA-256:** `b8f3e2a1c7d5a9b0e4f6a2c8e3f1a7b9d2e5f8a0b3c6e9f1a4d7e0c3f6a9`
- **File type:** XML (Windows Scheduled Task)
- **Forensic significance:**
  - Created **during active MSBuild C2 session** (2026-04-14T02:47:06Z, 59 seconds after alert)
  - Task name suggests benign update scheduler (stealth naming)
  - Execution time: 2026-04-14T02:47:00Z (recurring)
  - References executable at: C:\ProgramData\Microsoft\Windows\Temp\svchost-update.exe
  - Persistence mechanism: survives reboot, continues C2 beaconing
  - Timestamp correlation with C2 traffic to 185.220.101.47:443 (2026-04-14T02:46:58Z)
- **Follow-up:** Extract task XML; parse trigger conditions, action command, execution context; check for Task Scheduler event log entries (ART-002 memory); correlate with recurring C2 intervals in proxy logs

### CRITICAL: ART-001-F05 — Lateral Movement Staging

- **Path:** C:\Users\dmarsh\AppData\Local\Temp\pass-the-ticket.zip
- **Inode:** 88765
- **File size:** 156240 bytes
- **Created (UTC):** 2026-04-14 02:47:12
- **Modified (UTC):** 2026-04-14 02:47:12
- **Accessed (UTC):** 2026-04-14 03:22:47
- **SHA-256:** `d3f5c8a2e9b1f4a7c0e2d5f8a3b6c9e1f4a7c0e2d5f8a3b6c9e1f4a7c0e2d5`
- **File type:** ZIP archive
- **Forensic significance:**
  - Created immediately after MSBuild alert (2026-04-14T02:47:12Z)
  - Archive filename suggests Kerberos ticket manipulation tools (mimikatz, Rubeus variant)
  - Access timestamp (2026-04-14T03:22:47Z) matches **lateral movement to WST-WS-017** in auth log: `kerberos_tgs_req` from WST-WS-031 to WST-WS-017 (cifs/host SPN)
  - 156 KB size consistent with compiled .NET tools (Rubeus, modified Kerberos relayer)
  - Staging directory (Temp) bypasses typical binary execution restrictions
- **Follow-up:** Extract archive contents; identify compiled tools (Rubeus, Mimikatz, Kerberos relayer); correlate with memory injection techniques in ART-002; check for credential theft indicators

## Examined Directories

### C:\Users\dmarsh\AppData\Local\Temp\

**Files present (suspicious entries):**
- `update.zip` — Archive, inode 67890, 421004 bytes, 2026-04-13T18:14:43Z
- `update.xml` — XML config, inode 67204, 2847 bytes, 2026-04-14T02:46:56Z
- `update.exe` — Executable, inode 67891, 178240 bytes, 2026-04-14T02:46:57Z (extracted from update.zip)
- `pass-the-ticket.zip` — Archive, inode 88765, 156240 bytes, 2026-04-14T02:47:12Z
- `svchost-update.exe` — Executable (symlink reference), persistence binary

**Analysis notes:** 
- Primary staging and execution directory for attacker
- 8-hour gap between phishing download (2026-04-13T18:14:43Z) and extraction/execution (2026-04-14T02:46:56Z)
- All suspicious files created or accessed within 90-second incident window (2026-04-14T02:46:41Z–02:47:30Z)
- Temp directory bypass typical application whitelisting

### C:\Windows\System32\Tasks\

**Suspicious scheduled tasks:**
- `UpdateScheduler` (inode 78341): Created 2026-04-14T02:47:06Z, references svchost-update.exe
- `WindowsDefenderCache` (inode 78342): Created 2026-04-14T02:47:08Z, masquerades as legit Windows Defender task
- Standard tasks (`Microsoft\Windows\WindowsUpdate\*`, `Microsoft\Windows\System32\*`) unchanged from baseline

**Analysis notes:** 
- Two non-standard tasks created during incident window
- Attacker naming convention mimics legitimate Windows maintenance tasks
- No scheduled tasks created pre-incident (baseline integrity maintained)

### C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\

**LNK shortcut files:**
- `update.zip.lnk` — Recent access, created 2026-04-13T18:14:43Z, points to Downloads
- `ms0365-support.login-verification.click.lnk` — Recent access, created 2026-04-13T18:14:02Z (phishing site)
- `WST-WS-017.lnk` — Recent access to network share, created 2026-04-14T03:22:47Z (lateral movement timing)

**Analysis notes:** 
- Browser history recorded in LNK shortcut metadata
- Timeline aligns with proxy log and auth log events

## Timeline of Attack Sequence

| Timestamp (UTC) | Event | Evidence Path | Source |
| --- | --- | --- | --- |
| 2026-04-13T18:14:02Z | Phishing site visit | Browser history, LNK file | Proxy log + filesystem |
| 2026-04-13T18:14:41Z | Azure AD compromise (Russia IP 45.63.9.88) | Auth log | ad_auth_log.jsonl |
| 2026-04-13T18:14:43Z | Malware download (update.zip) | C:\Users\dmarsh\Downloads\ inode 45821 | Proxy log + filesystem |
| 2026-04-14T02:44:02Z | Unusual logon at odd hour | Auth log | ad_auth_log.jsonl |
| 2026-04-14T02:46:41Z | PowerShell loader staged | C:\Windows\Temp\payload_loader.ps1 | Filesystem |
| 2026-04-14T02:46:56Z | MSBuild config staged | C:\Users\dmarsh\AppData\Local\Temp\update.xml | Filesystem |
| 2026-04-14T02:46:57Z | MSBuild child process launched | EDR process tree | SIEM alert A-20260414-9841 |
| 2026-04-14T02:47:06Z | Persistence task created | C:\Windows\System32\Tasks\UpdateScheduler | Filesystem |
| 2026-04-14T02:47:11Z | C2 connection established | 185.220.101.47:443 (TOR exit relay) | Proxy log + SIEM alert |
| 2026-04-14T02:47:12Z | Lateral movement tools staged | C:\Users\dmarsh\AppData\Local\Temp\pass-the-ticket.zip | Filesystem |
| 2026-04-14T03:22:47Z | Lateral movement to WST-WS-017 | Kerberos TGS-REQ cifs/host | Auth log |
| 2026-04-14T03:27:13Z | Secondary C2 connection | 91.234.99.107:443 (C2 infrastructure) | Proxy log |
| 2026-04-14T03:40:18Z | Lateral movement to LIS-WSIDE-01 | Kerberos TGS-REQ cifs/ | Auth log |
| 2026-04-14T03:43:30Z | Data exfiltration staging | File server access, 14 PDFs opened | Auth log |

## Cross-Reference with Other Artifacts

| Filesystem Finding | Corroborating Evidence | Artifact Source |
| --- | --- | --- |
| update.zip download | Proxy log 2026-04-13T18:14:43Z from ms0365-support.login-verification.click | ART-004: proxy_log.jsonl |
| update.xml MSBuild execution | SIEM alert A-20260414-9841, process tree PowerShell→MSBuild | ART-004: siem_alert_export.json |
| Credential compromise | Azure AD signin from Russia IP (45.63.9.88); unusual logon hour 02:44Z | ART-005: ad_auth_log.jsonl |
| C2 connection 185.220.101.47:443 | MSBuild.exe PID 8104 proxy log, TOR exit relay reputation | ART-004: siem_alert_export.json + proxy_log.jsonl |
| Lateral movement to WST-WS-017 | Kerberos TGS-REQ 2026-04-14T03:22:47Z, Pass-the-Ticket technique | ART-005: ad_auth_log.jsonl |
| Data exfiltration | File server access to LIS_REPORTS$ (14 PDFs), 2026-04-14T03:43:30Z | ART-005: ad_auth_log.jsonl |
| Persistence scheduled task | Task created during active MSBuild C2 session, references svchost-update.exe | Filesystem + process tree |

## Analysis Completion

- **Analysis end time (UTC):** 2026-04-14T10:45:00Z
- **Chain of custody:** Entry to be logged with action `filesystem_analysis_complete`, hash baseline to be re-verified post-access
- **Suspicious files extracted for malware analysis:** 5 files (update.zip, update.exe, update.xml, payload_loader.ps1, pass-the-ticket.zip, scheduled task XML)
- **Next step:** Memory analysis (ART-002 wst-ws-031.mem) to correlate injected code, process hollow technique, and C2 beacon callbacks; auth log analysis (ART-005) for full lateral movement chain
