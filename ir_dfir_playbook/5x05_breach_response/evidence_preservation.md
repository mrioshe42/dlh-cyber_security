# Evidence Preservation: IR-2026-0420-01

## Priority Order

| Priority | Host | Reason | Acquisition |
|----------|------|--------|-------------|
| 1 | CS-WS-101 | Initial compromise; memory pre-acquired (19:38Z); credential dumping + ransomware staging; active C2 at 19:32Z | Memory: verify Torres hash; Disk: FTK before isolation |
| 2 | CS-WS-104, CS-WS-107 | Active C2 beacons (2026-04-19T00:04, 00:12Z); ransomware staging scripts | Memory: WinPmem before isolation |
| 3 | FILE-SVR-01 | Lateral movement (2026-04-19T02:14Z); PHI access risk; no active beacon | Memory: WinPmem; Disk: VSS (large file server) |
| 4 | CS-WS-112 | Latest lateral movement (2026-04-19T00:18Z); lower volatility | Memory: WinPmem |
| 5 | SCHED-SVR-01 | Explains 90+ min disk activity (svchost32.exe spawned 2026-04-20T18:02Z); exfiltration staging risk | Memory + Disk: VSS |

## Artifacts & Acquisition Commands

| ID | Host | Type | Tool | Command | Duration | Window | Hash Verified |
|----|------|------|------|---------|----------|--------|---------------|
| ART-001 | CS-WS-101 | Memory | WinPmem | Torres 19:38Z (pre-call) | — | — |  NOT COMPUTED (re-verify at 20:10Z) |
| ART-002 | CS-WS-101 | Disk | FTK Imager | `ftkimager /start /device \\.\PhysicalDrive0 /destination \\evidence\share\IR-2026-0420-01\cs-ws-101.dd /case ir-2026-0420-01 /verify` | 60–90 min | 19:58–20:45Z | Post-transfer |
| ART-003 | CS-WS-104 | Memory | WinPmem | `psexec \\CS-WS-104 -s -c winpmem_3.9.1.exe -o \\evidence\share\IR-2026-0420-01\cs-ws-104.mem` | 25 min | 19:55–20:20Z | Post-transfer |
| ART-004 | CS-WS-107 | Memory | WinPmem | `psexec \\CS-WS-107 -s -c winpmem_3.9.1.exe -o \\evidence\share\IR-2026-0420-01\cs-ws-107.mem` | 25 min | 19:55–20:25Z | Post-transfer |
| ART-005 | FILE-SVR-01 | Memory | WinPmem | `psexec \\FILE-SVR-01 -s -c winpmem_3.9.1.exe -o \\evidence\share\IR-2026-0420-01\file-svr-01.mem` (domain admin) | 40 min | 20:10–20:50Z | Post-transfer |
| ART-006 | FILE-SVR-01 | Disk | FTK Imager | `ftkimager /start /device \\.\PhysicalDrive0 /destination \\evidence\share\IR-2026-0420-01\file-svr-01.dd /case ir-2026-0420-01 /verify /VSS` | 120–180 min | 20:15–22:30Z | Post-transfer |
| ART-007 | CS-WS-112 | Memory | WinPmem | `psexec \\CS-WS-112 -s -c winpmem_3.9.1.exe -o \\evidence\share\IR-2026-0420-01\cs-ws-112.mem` | 25 min | 20:45–21:10Z | Post-transfer |
| ART-008 | SCHED-SVR-01 | Memory | WinPmem | `psexec \\SCHED-SVR-01 -s -c winpmem_3.9.1.exe -o \\evidence\share\IR-2026-0420-01\sched-svr-01.mem` (domain admin) | 30 min | 20:30–21:00Z | Post-transfer |
| ART-009 | SCHED-SVR-01 | Disk | FTK Imager | `ftkimager /start /device \\.\PhysicalDrive0 /destination \\evidence\share\IR-2026-0420-01\sched-svr-01.dd /case ir-2026-0420-01 /verify /VSS` | 60–90 min | 20:45–22:15Z | Post-transfer |

## Volatile Collections (All Hosts, Parallel Post-Memory)

```bash
# Registry
reg export HKLM\SYSTEM \\evidence\share\IR-2026-0420-01\[host]\SYSTEM.hiv /y
reg export HKLM\SOFTWARE \\evidence\share\IR-2026-0420-01\[host]\SOFTWARE.hiv /y

# Event logs
wevtutil epl Security \\evidence\share\IR-2026-0420-01\[host]\Security.evtx /overwrite:true
wevtutil epl System \\evidence\share\IR-2026-0420-01\[host]\System.evtx /overwrite:true
wevtutil epl "Microsoft-Windows-Sysmon/Operational" \\evidence\share\IR-2026-0420-01\[host]\Sysmon.evtx /overwrite:true

# Live state
tasklist /v /fo csv > \\evidence\share\IR-2026-0420-01\[host]\tasklist.csv
netstat -anbo > \\evidence\share\IR-2026-0420-01\[host]\netstat.txt
Get-Service | ConvertTo-Csv > \\evidence\share\IR-2026-0420-01\[host]\services.csv
```

**Timing:** 20:30–21:30Z (parallel with ART-005, ART-006, ART-008, ART-009)

## Hash Verification

**All artifacts use SHA-256; computed at acquisition (FTK) or post-transfer (WinPmem).**

```bash
# Batch verification (Scribe, 20:10Z–21:00Z)
for %%f in (\\evidence\share\IR-2026-0420-01\*.mem) do certutil -hashfile %%f SHA256 >> hash_verification.txt

# Cross-check against source manifests
# If mismatch → evidence quarantined, reacquired
```

**ART-001 (cs-ws-101.mem) CRITICAL:** Torres did NOT compute hash. Verify against any available source hash at acquisition time; if unavailable, document "hash computed in custody" with 20:10Z timestamp.

## Chain of Custody Table

| Entry | Artifact | Host | Type | Acquired By | Acquired At | Verified By | Verified At | Storage Path | Status |
|-------|----------|------|------|-------------|-------------|-------------|-------------|--------------|--------|
| 001 | ART-001 | CS-WS-101 | Memory | Mike Torres | 2026-04-20T19:38:18Z | Scribe | 2026-04-20T20:10Z | \\evidence\share\IR-2026-0420-01\cs-ws-101.mem |  Hash NOT recorded by Torres |
| 002 | ART-002 | CS-WS-101 | Disk | FTK/Jumpbox | 2026-04-20T19:58–20:45Z | Scribe | 2026-04-20T21:00Z | \\evidence\share\IR-2026-0420-01\cs-ws-101.dd | FTK manifest with MD5/SHA-256 |
| 003 | ART-003 | CS-WS-104 | Memory | Scribe/WinPmem | 2026-04-20T19:55–20:20Z | Scribe | 2026-04-20T20:35Z | \\evidence\share\IR-2026-0420-01\cs-ws-104.mem | Verified post-transfer |
| 004 | ART-004 | CS-WS-107 | Memory | Scribe/WinPmem | 2026-04-20T19:55–20:25Z | Scribe | 2026-04-20T20:40Z | \\evidence\share\IR-2026-0420-01\cs-ws-107.mem | Parallel with ART-003 |
| 005 | ART-005 | FILE-SVR-01 | Memory | Scribe/WinPmem | 2026-04-20T20:10–20:50Z | Scribe | 2026-04-20T21:10Z | \\evidence\share\IR-2026-0420-01\file-svr-01.mem | Domain admin context |
| 006 | ART-006 | FILE-SVR-01 | Disk | FTK/Jumpbox | 2026-04-20T20:15–22:30Z | Scribe | 2026-04-20T23:00Z | \\evidence\share\IR-2026-0420-01\file-svr-01.dd | VSS; large file (verify capacity) |
| 007 | ART-007 | CS-WS-112 | Memory | Scribe/WinPmem | 2026-04-20T20:45–21:10Z | Scribe | 2026-04-20T21:25Z | \\evidence\share\IR-2026-0420-01\cs-ws-112.mem | Verified post-transfer |
| 008 | ART-008 | SCHED-SVR-01 | Memory | Scribe/WinPmem | 2026-04-20T20:30–21:00Z | Scribe | 2026-04-20T21:30Z | \\evidence\share\IR-2026-0420-01\sched-svr-01.mem | Domain admin context |
| 009 | ART-009 | SCHED-SVR-01 | Disk | FTK/Jumpbox | 2026-04-20T20:45–22:15Z | Scribe | 2026-04-20T22:45Z | \\evidence\share\IR-2026-0420-01\sched-svr-01.dd | VSS; parallel with ART-006 |
| 010+ | ART-010–044 | ALL | Registry/Logs/Snapshots | Wazuh/PSExec | 2026-04-20T20:30–21:30Z | Scribe | 2026-04-20T22:00Z | \\evidence\share\IR-2026-0420-01\[host]\* | Batch verification |

**Handoff to Forensic Analysis:** 2026-04-20T23:00Z (all hashes verified, manifest signed by Scribe)

## Execution Timeline

```
19:38Z — ART-001 acquired by Torres (hash missing)
19:52Z — Incident declared; evidence preservation begins
19:55Z — ART-003, ART-004 captures begin (parallel)
19:58Z — ART-002 disk capture begins (~90 min)
20:10Z —  ART-001 hash verification MUST complete (re-acquire if mismatch)
20:10Z — ART-005 memory capture begins
20:15Z — ART-006 disk capture begins (~180 min)
20:30Z — ART-008 memory capture + volatile collections (registry, logs, snapshots)
20:45Z — ART-007 memory capture + ART-009 disk capture begins
21:00Z — ART-002, ART-003, ART-004, ART-005 transfers complete
21:30Z — All memory captures complete
22:00Z — Volatile collections complete
22:45Z — ART-006, ART-009 disk transfers complete
23:00Z — All hash verification complete; ready for forensic analysis
```

## Critical Issues

1. **ART-001:** Hash not computed by Torres (protocol violation, repeats IR-2026-0414-01). Scribe must verify at 20:10Z; re-acquire if no source hash available.

2. **FILE-SVR-01.dd size:** May be 500 GB–2 TB. If exceeds evidence share capacity, capture critical partition (C:\ + data volumes) only.

3. **Network isolation timing:** Plan assumes isolation does NOT occur before 21:00Z. If IR Commander orders earlier isolation, compress acquisition sequence.

4. **Ransomware staging scripts:** encryption_staging.ps1 staged on all workstations/file server but NOT YET EXECUTED at 19:52Z. Monitor C2 traffic during capture for execution command (escalates to SEV1 if triggered).
