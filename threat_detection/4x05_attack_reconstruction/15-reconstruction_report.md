# HEALTHBANE Attack Reconstruction Report

**MedDefense Health Systems · ticket MD-2026-IR-0414-001 · evidence cut-off 2026-05-18 · IR Restricted**
Times are UTC (CDT = UTC-5). Evidence tags: 4x00-4x04 (earlier investigations), MEM (memory), DISK, FW (firewall), NOTES (IR notes). Confidence: **CONVERGED** = 2+ independent sources, **PROBABLE** = 1, **POSSIBLE** = inference.

## 1. Executive Summary

**What happened.** On 2026-04-14 the HEALTHBANE group phished a records clerk (Diane Marsh) and captured her password. That password was not the way in. On 04-15 a second email with a macro invoice was opened on WS-RECV-03 and installed a remote-access tool (RAT) that called home every 5 minutes. After three quiet weeks the attacker disabled antivirus scanning of a folder (05-04), dumped credentials from memory (05-05), and used a stolen service account to reach the patient database, the insurance database and the domain controller. Between 05-08 and 05-13 they copied the full patient and insurance tables and a directory of all domain accounts, uploaded them to their own server and deleted the copies.

**How far they got.** Systems: WS-RECV-03 (full control); SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01 (accessed). Data: **47,138 patient records** and **51,002 insurance records** (names, DOB, SSN column, diagnosis codes) plus 1,184 directory accounts and stolen credentials. **Exfiltration was completed**: the three staged files (34.4 MB) match three firewall uploads to `185.220.101.45:443` byte for byte. Nothing was interrupted; the staging folder was already empty at isolation.

**How it was stopped.** No alert is known to have led to detection. A proactive threat hunt (4x04) found PsExec/WMI/PowerShell-Remoting from a records workstation at 01:00-04:00 with NTLM logons on a Kerberos-only service account. The CISO authorised isolation at 13:38 CDT; the host was cut off at **13:42 CDT on 2026-05-15**. Memory was captured live, then the disk was imaged.

**What happens next.** (1) Start HIPAA, individual and state notification now: the breach threshold is met; the 60-day deadline is **2026-07-14**, and a 30-day state clock would end **2026-06-14**. (2) Rebuild WS-RECV-03 and rotate `svc_healthsync`, `records03` and the other service accounts; treat SRV-DC-01 as possibly compromised. (3) Block the attacker infrastructure and image the two databases and the DC. (4) Close the paths used (section 8).

| Metric | Value |
|---|---|
| Dwell time | 31.2 days (04-14 13:18Z to 05-15 18:42Z); 30.4 days from the RAT foothold |
| Breakout (foothold to first lateral move) | 20.9 days |
| Foothold to scheduled task / first staged file | 21.9 / 22.9 days |
| First upload to isolation | 7.5 days |
| ATT&CK | 25 of 29 techniques CONFIRMED (86%); 28 of 32 with three new ones; baseline layer recounts to 22 of 29 (75%), not the filed 80% |

## 2. Methodology

- **Sources** (13 files, script `0`): 4x00-4x04 summaries (MEDIUM), memory image, disk image and firewall export (HIGH), IR notes (LOW, context only), plus IOC master, ATT&CK layer, asset inventory and topology.
- **Approach:** every IOC, event and technique was searched in all sources; timestamps normalised to UTC (firewall-only times shifted -4 s for its declared skew); where sources disagreed, the agreeing primary sources were adopted. 4x02 and the IR notes never count as independent. Each step is a script (`0` to `12`) that parses the files; scripts 6, 10, 11, 13 and 14 did not exist, so Stage 3, the defensive evaluation and the remediation plan are derived directly from the evidence.
- **Limitations:** only WS-RECV-03 was imaged (no server images or SQL audit); no network capture 04-17 to 05-01; no host telemetry before the 04-22 reboot; the firewall export is abridged (explicit rows plus class totals out of 39,412 sessions); host/IP labels disagree across documents (firewall: HEALTH-DB 10.10.20.30, INS-DB .31; inventory and topology: .15 and .25), so database identity rests on names, not IPs.

## 3. Attack Reconstruction

**Stage 1, initial access (04-14).** E1 reached 14 staff (SPF hardfail, DKIM missing, DMARC fail) at 13:14:22. Diane clicked at 13:18:05 and her credentials were POSTed to the lookalike portal at **13:18:42** (CONVERGED: 4x00, 4x01). T1566.002, T1078 (obtained, never shown used). 4x00's "17-minute exposure" is wrong by its own times: rotation came 78 s after the POST; 17 minutes is the delay to the helpdesk report.

**Stage 2, C2 establishment (04-15).** At 08:43:18 a second mail with `April-Invoice-MD2026.docm` was released from quarantine by the helpdesk without an attachment check. The macro ran, fetched the RAT (287,444 B) at 08:51:11 and the first beacon followed at **08:51:38**, 19h32m after the credential theft (CONVERGED: 4x01, 4x03, DISK). T1566.001, T1204.002, T1059.005, T1105, T1071.001, T1573.001. Beaconing continues unchanged in the firewall data (05-02 to 05-15, 3,958 sessions, same JA3 as 4x01). The secondary C2 `203.0.113.47:8443` first appears 05-07 06:48:07Z; it was *not observed* earlier, but nothing could have shown it (no firewall before 05-02, PCAP ended 04-16), so "not operational during Stage 2" cannot be claimed. T1568 is not supported (fixed IPs).

**Stage 3, malware and tooling (04-21 to 05-07).** AV quarantined the RAT on 04-21; a new copy appeared 21 s after the 04-22 reboot with a Run-key and a forged parent process (MEM, DISK); how it returned is unexplained. The exfiltrator script arrived on 04-30 inside a C2 response. Defender exclusion for `C:\Windows\Temp` was written 05-04 23:11 under the `records03` token (R. Kim claims it; attacker PROBABLE). The scheduled task "HealthSync Update Service" (daily 02:00, hidden) was created 05-07 06:47:33 (MEM, DISK) and the secondary C2 opened 38 s later. T1547.001, T1036.005, T1055.012, T1562.001, T1053.005, T1571.

**Stage 4, lateral movement and exfiltration (05-05 to 05-15).**
- Credentials: LSASS dump #1 05-05 08:22:14 (`debug_tool.exe`, `svc_healthsync` inside `out.dat`), dump #2 05-12. T1003.001.
- Pivots with `svc_healthsync` over NTLM using a copied `PsExec64.exe`: SRV-HEALTH-DB 05-06 07:11:42, SRV-INS-DB 05-09 07:46:11, SRV-DC-01 05-13 07:08:56 (CONVERGED: 4x04, DISK prefetch, FW). 4x04's times for pivots #2 and #3 are 54 and 13 minutes off the prefetch/firewall pair; prefetch and firewall were adopted. T1021.002, T1047, T1021.006, T1550.002, T1078.002.
- Exports (CONVERGED: DISK, FW, MEM): 05-08 patients table, 14.2 MB; 05-11 insurance table, 11.8 MB; 05-13 AD users, 8.4 MB. Flow: SQL/LDAP to `%TEMP%\out_*.csv` on WS-RECV-03, `Compress-Archive` to `C:\Users\Public\Tmp`, HTTPS POST to the C2, files deleted. T1005, T1560.001, T1074.001, T1041, T1070.004.
- Anti-forensics: Security log cleared 05-09 08:00-08:12Z, inside the SMB session to SRV-INS-DB (not during the second exfiltration, as the disk report says). Discipline was basic: VSS, USN journal, prefetch and `$MFT` untouched. T1070.001.
- Containment: the last task run (05-15 07:00Z) sent only 4,218 B; nothing was pending. Uncontained, the daily task and the 3-4 day pivot / 2-3 day upload rhythm would have continued, with credentials and the directory the likely next targets (POSSIBLE, extrapolated from three points).
- Open: the firewall shows no SQL port 1433 and no cross-VLAN session large enough to carry the exports (the 47 such sessions are only aggregated), so the bulk pull is unverified; which credential the 05-08 task query used is unexplained; why `svc_healthsync` material was on a records workstation is unexplained.

## 4. Unified Timeline

| Time (UTC) | Event | ATT&CK | Conf. |
|---|---|---|---|
| 04-14 13:18:42 | Credentials POSTed to lookalike portal | T1566.002, T1078 | CONVERGED |
| 04-15 08:43:18 | Macro dropper mail released from quarantine | T1566.001 | CONVERGED |
| 04-15 08:51:38 | RAT installed; first C2 beacon | T1105, T1071.001 | CONVERGED |
| 04-22 06:14 | RAT re-created after AV quarantine; Run-key | T1547.001 | CONVERGED |
| 05-04 23:11 | Defender exclusion | T1562.001 | CONVERGED |
| 05-05 08:22 | LSASS dump #1 (uploaded in ~80 small sessions) | T1003.001 | CONVERGED |
| 05-06 07:11 | Pivot #1 SRV-HEALTH-DB | T1021.002, T1550.002 | CONVERGED |
| 05-07 06:47 / 06:48 | Scheduled task / secondary C2 opens | T1053.005, T1571 | CONVERGED |
| 05-08 07:36-07:38 | Patient export staged, uploaded | T1005, T1560.001, T1041 | CONVERGED |
| 05-09 07:46 / 08:00 | Pivot #2 SRV-INS-DB / log cleared | T1021.002, T1070.001 | CONVERGED |
| 05-11 08:14-08:17 | Insurance export staged, uploaded | T1005, T1041 | CONVERGED |
| 05-12 07:45 | LSASS dump #2 | T1003.001 | CONVERGED |
| 05-13 07:08 / 07:34 | Pivot #3 SRV-DC-01 / AD export uploaded | T1021.002, T1041 | CONVERGED |
| 05-15 18:38 / 18:42 | Isolation authorised / executed | - | CONVERGED |

33 events in total, 28 CONVERGED (84%), 1 single-source. **Metrics:** see section 1; operational tempo is a milestone every 3.8 days, with 17 of 19 events after 05-04 at 01:00-04:00 CDT.

**Gaps:** 04-15 to 04-21 (collection gap, 27% covered); 04-22 to 04-30 (8 days, covered by the disk journal, no hands-on activity found: dormant or beacon-only); 04-30 to 05-04 and 05-09 to 05-11 (quiet). No network capture 04-17 to 05-02.

**Not sequenced with confidence:** the hunt itself. 4x04 dates its start and escalation 05-18, triggered by an advisory of 05-17, yet its own R1-R3 and IR note #001 place the response on 05-15. The isolation (three sources) is firm; the hunt start is not, so "detection to containment" is only known as 4 minutes from authorisation to isolation. Also unprovable: order of file deletion vs upload on 05-08 (same second), and how the RAT came back on 04-22.

## 5. ATT&CK Analysis

32 techniques: the 29 in the baseline layer plus T1562.001, T1070.004, T1571 found only in IR evidence.
- **Upgraded to CONFIRMED:** T1041 (all uploads seen; the baseline said "interrupted at staging"), T1005.
- **New (not covered before):** T1053.005, T1074.001, T1560.001, T1070.001, T1070.004, T1562.001, T1571.
- **Corrected:** T1048.003. The exfiltration channel was HTTPS (`c2_post`); DNS carried only two test queries.
- **Downgraded:** T1550.002 (4x04: pass-the-hash "cannot be proven"), T1583.001 (single source), T1112 (the `PSEXESVC` key is in no evidence file).
- **Unchanged, 22 techniques**, including T1566.001 whose rationale is corrected (the macro attachment, not the click).

| Milestone | As filed | Recounted from the files |
|---|---|---|
| Post-4x02 | 38% observed, 55% mapped | 27% / 51% |
| Post-4x04 layer | 80% observed, 90% mapped | 75% / 86% |
| Post-4x05 | - | 86% CONFIRMED (25/29); 93% with PROBABLE (30/32) |

Remaining gap (4 of 32): T1048.003 (not employed), T1583.001, T1550.002, T1112 (need server or DC logs; those hosts were not imaged).

## 6. Impact Assessment

| Data | Host | Status |
|---|---|---|
| Patient PHI (name, DOB, SSN column, diagnoses) | SRV-HEALTH-DB | **EXFILTRATED**, 47,138 rows = whole `patients` table |
| Insurance/billing (name, SSN, plan) | SRV-INS-DB | **EXFILTRATED**, 51,002 rows |
| Directory and credentials | SRV-DC-01, WS-RECV-03 | **EXFILTRATED**, 1,184 accounts; NTDS.dit: no evidence either way |
| Employee HR records, imaging PHI | SRV-FILE-01 | No evidence of access (IP conflict keeps it open) |

- **Exfiltration:** staged 34.4 MB; transmitted 34.4 MB to `185.220.101.45:443`; secondary C2 carried 14 KB. Credential dumps were uploaded separately.
- **HIPAA breach threshold: MET** (98,140 exported rows; unique individuals unresolved: inventory 50,000-55,000 vs IR notes 78,000-82,000, both far above 500). If the 04-22 Run-key alert fired and was missed, a regulator could date discovery earlier (60 days from 04-22 is 2026-06-21).
- **Mitigating factors: none strong.** SSNs are encrypted at rest, but the data was read through an authorised account, so no safe harbour applies; whether exported SSNs were ciphertext is unverified.

## 7. Defensive Posture

**Worked:** user report and password rotation within 78 s; mail-gateway and Wazuh 100080/100081 rules; the behavioural hunt (15 anomalous events against 93 legitimate admin events), which was the only control that found Stage 4; firewall logs unaffected by host log clearing; live memory capture and intact prefetch/USN/VSS; 4-minute decision-to-isolation.

**Failed:** helpdesk released the attachment and macros ran; AV quarantine on 04-21 was not investigated; the Run-key rule (100091) has no recorded outcome; local administrator on records workstations and a shared `records03` account; Defender exclusions writable from a user context; service accounts allowed NTLM from workstations; the `users-to-server-segment` rule let any workstation reach servers; 81 MB left to one external IP with no egress control or alert; no SQL audit, no scheduled-task logging, 48-hour PCAP.

**Lesson:** the attack was found by behaviour, not signature, after 31 days. One opened attachment, one local-admin host and one service account were enough to reach the crown jewels.

## 8. Remediation Plan

| When | Action | Why |
|---|---|---|
| 0-72 h | Start notifications; plan on the shortest state clock (06-14) | Threshold met |
| 0-72 h | Block `185.220.101.45/.46`, `203.0.113.47`, `*.healthbane-c2.net`; sweep for the IOCs | Active C2 and fallback |
| 0-72 h | Rotate `svc_healthsync`, `records03`, `dmarsh`, `svc_insurance`, `svc_backup`; reset cached credentials of WS-RECV-03 users | Two LSASS dumps; AD export listed all service accounts |
| 0-72 h | Image SRV-DC-01, SRV-HEALTH-DB, SRV-INS-DB; export SQL logs; decide on KRBTGT double rotation | DC access confirmed, read-only unproven |
| 0-72 h | Re-image WS-RECV-03 after evidence sign-off; hunt VLAN-3 (incl. WS-RECV-04/-07) for the tools | The RAT re-launches itself; one unverified claim of spread |
| 1-6 wk | Block Office macros and require attachment checks before helpdesk release | Stage 1-2 entry |
| 1-6 wk | Remove local admin from records workstations; named users instead of `records03`; Credential Guard / LSASS protection; tamper-protect Defender | Stages 3-4 |
| 1-6 wk | `svc_*` Kerberos-only, no workstation logon; restrict workstation-to-server rules to application ports; server and records-VLAN egress allow-list | Pass-the-hash, lateral movement, exfiltration |
| 1-6 wk | Detections: scheduled-task creation, Defender exclusion changes, log clearing (1102), Run-key `HealthSync`, large outbound to new IPs; enable SQL Server audit | Closes the hunt's own gaps |
| 1-3 mo | Tiered admin (PAWs only for PsExec/WMI/WinRM); EDR with parent-process telemetry; 30-day network capture at the VLAN-3/20 boundary; memory-capture and imaging playbook; recurring hunts and purple-team replay | Detection in hours, not 31 days |

Priority: the first group covers legal exposure and assets the attacker may still hold; the second breaks a different stage each, so no single barrier must hold (server-reach and service-account restrictions alone would have stopped Stage 4).

## 9. Conclusions

- **Detection is not understanding.** The hunt proved a workstation was driving admin tools against servers. Only the reconstruction showed the data had already left, that the stolen password was never the foothold, and that the RAT survived a quarantine.
- **Piecemeal investigation hides contradictions.** Each phase was right about its slice: 4x01 could not see lateral movement; 4x04 named gaps it could not close; three phases' coverage numbers do not recount; hunt timestamps were off by 13 and 54 minutes. These only appear on one clock.
- **Hunting and forensic readiness are necessities.** No preventive control stopped the attacker in 31 days. The reconstruction was possible because the attacker left prefetch, USN and VSS intact and the memory capture preserved the live C2 socket; neither can be assumed next time.
- **Still unknown:** activity 04-16 to 05-01; what exactly was read on the databases and the bulk-pull path (SQL audit, server images); whether DC secrets or SRV-FILE-01 were touched (DC and file-server images, DNS/ARP to settle IPs); how the RAT returned on 04-22 (AV/Wazuh logs of 04-21/22, rule 100091 outcome); where `svc_healthsync` material came from; unique individuals affected; whether exported SSNs were ciphertext; other VLAN-3 hosts; when the hunt really began.

## Appendix A. IOC Summary (31 in the master, plus 5 new)

- **Converged (19):** meddefense-portal.com, healthbane-c2.net, sync/update.healthbane-c2.net, 185.220.101.45, 185.220.101.46, HEALTHBANE_S2_invoice.docm, svchost_update.exe SHA256 `c8e2a9b4...`, Run-key `HKCU\...\Run\HealthSync`, sync_healthdata.ps1 SHA256 `f1e8a4c7...`, dmarsh, svc_healthsync, debug_tool.exe, PsExec64.exe, stage1.ps1, WS-RECV-03, SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01.
- **Single-source (5):** meddefense-benefits.com, outlook-protection.com, data-sync.healthbane-c2.net (4x01 only), the portal login URL, docm SHA256 `9a2f3e7b...` (4x03 only).
- **Conflicted (2):** `svchost_update.exe` (master 04-14, delivered 04-15, born on disk 04-22); `sync_healthdata.ps1` (master 05-06, disk 04-30).
- **Master-only (1):** `HKLM\...\Services\PSEXESVC`, in no evidence file.
- **Detection artifacts (4):** Wazuh 100080, `wlb_ntlm_offhours`, YARA dropper rule, off-hours NTLM pattern.
- **New from IR:** `203.0.113.47:8443` (secondary C2; FW, MEM, DISK; a duplicate ID NEW-006 exists), task "HealthSync Update Service" (MEM, DISK), `debug_tool.exe` SHA256 `4d2a8f5b...` (DISK only), Defender exclusion `C:\Windows\Temp` (MEM, DISK), staging names `out_<ts>.csv`, `staging_export_NNN.zip`, `query_results.csv` (DISK, FW).

## Appendix B. Evidence Citation Index

4x00 `previous_findings/4x00_phishing_summary.txt` · 4x01 `4x01_network_timeline.txt` (T-001..T-299) · 4x02 `4x02_attack_mapping.json` · 4x03 `4x03_malware_summary.txt` (S1-S3) · 4x04 `4x04_hunting_report.txt` (H1-H5) · MEM `ir_evidence/memory_artifacts.txt` (§3 netscan, §6 script blocks, §9 K1-K5) · DISK `disk_forensics_report.txt` (§3 F1-F5, D1-D5; §4 task XML; §5 prefetch; §6 MFT) · FW `firewall_sessions_ws_recv_03.json` (KNOWN_C2, SECONDARY_C2, EXFIL_BURST, LATERAL_MOVEMENT) · NOTES `ir_team_notes.txt` (#001-#010) · reference: IOC master, ATT&CK layer, asset inventory, network topology. Every figure is reproducible with `./N-name.sh` for N in 0-5, 7-9, 12.

## Appendix C. ATT&CK Navigator Layer Reference

Baseline `reference/attck_navigator_80pct.json` (29 techniques); no final layer file was produced. Final states: **CONFIRMED (28):** T1566.001, T1566.002, T1204.002, T1059.001, T1059.005, T1547.001, T1071.001, T1071.004, T1573.001, T1027, T1027.010, T1140, T1105, T1041, T1005, T1003.001, T1021.002, T1021.006, T1047, T1078, T1078.002, T1053.005, T1074.001, T1560.001, T1070.001, T1070.004, T1562.001, T1571. **PROBABLE (2):** T1583.001, T1550.002. **POSSIBLE (2):** T1048.003 (corrected), T1112 (downgraded).
