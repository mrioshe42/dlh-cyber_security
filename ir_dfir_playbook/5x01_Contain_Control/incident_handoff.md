# Incident Handoff: IR-2026-0414-01

Authoritative, self-contained record. All times UTC (2026-04-14 unless stated).

## 1. Incident Identity

| incident_id | severity | declared_at | closed_at | IR Commander | Scribe |
|---|---|---|---|---|---|
| IR-2026-0414-01 (alias IR-20260414-01) | **SEV1** (SEV2 at 02:52:18Z, raised 03:45:00Z) | 2026-04-14T02:52:18Z | **Open**: recovery validated 14:25Z; pending HIPAA assessment and eradication sign-off | James Chen, SOC Lead | Massimo, on-call SOC |

## 2. Executive Summary

- 04-13 18:14Z: dmarsh phished at `ms0365-support[.]login-verification[.]click`; credentials submitted, `update.zip` downloaded.
- 02:44–02:47Z: persistence → PowerShell → MSBuild → C2 185.220.101.47 (Tor) on WST-WS-031; wz-edr-100041 fired 02:47:11Z.
- WST-WS-031 isolation (03:19Z) was incomplete: the host still reached the domain controllers at 03:22:47Z.
- Pass-the-Ticket (dmarsh) gave lateral movement WST-WS-031 → WST-WS-017 (C2 91.234.99.107) → LIS-WSIDE-01.
- **PHI accessed:** 14 LIS report PDFs read 03:43:30Z; exfiltration not established; HIPAA assessment open.
- WST-WS-031 and WST-WS-017 rebuilt; both C2 IPs blocked (0 packets/24 h); recovery_validation.sh 6/6 PASS.

## 3. Scope

- **Users / accounts:** MEDDEFENSE\dmarsh (password phished; Kerberos tickets abused) · krbtgt (PtT; double reset required) · machine accounts of the 3 hosts.
- **Hosts:**

| Host | Evidence | First attacker activity | State |
|---|---|---|---|
| WST-WS-031 (10.42.118.31) | Payload, persistence, PS→MSBuild, C2 185.220.101.47 | 04-13 18:14:43Z | Rebuilt 10:12Z |
| WST-WS-017 (10.42.118.17) | PtT logon, ADMIN$, PS→MSBuild, C2 91.234.99.107 | 03:23:01Z | Rebuilt 11:04Z |
| LIS-WSIDE-01 | PtT logon, 14 PHI PDFs read | 03:42:08Z | Validated clean, not rebuilt |
| Other hosts with dmarsh tickets since 04-13 18:14Z | Unknown; hunt open (§9 #4) | — | — |

- **Data categories:** PHI (LIS daily lab results incl. microbiology; 14 files; patient count unknown) · credentials (dmarsh AD/O365) · Kerberos ticket material.

## 4. Timeline

Full contents of `incident_timeline.md`, append-only, unedited.

### Incident Timeline: IR-2026-0414-01

#### Header

- incident_id: IR-2026-0414-01 (alias in earlier artifacts: IR-20260414-01)
- declared_at: 2026-04-14T02:52:18Z
- declared_by: Massimo, on-call SOC
- initial_severity: SEV2
- current_severity: SEV1
- ir_commander: James Chen, SOC Lead
- scribe: Massimo

#### Legend

- OBSERVATION: Raw fact from an alert, log, or artifact
- DECISION: A choice made by an authorized actor, with rationale
- ACTION: An operation executed against an asset, with owner
- COMMUNICATION: A message sent or received, with audience
- EVIDENCE: A preserved artifact with hash and storage path

#### Entries
- 2026-04-13T18:14:02Z | OBSERVATION | SIEM proxy event | User dmarsh visited ms0365-support.login-verification.click/auth (phishing mimicry domain) via email referrer | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-13T18:14:41Z | OBSERVATION | SIEM proxy event | POST credentials submitted to malicious domain ms0365-support.login-verification.click/auth/submit returning 302 redirect | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-13T18:14:43Z | OBSERVATION | SIEM proxy event | Malware binary (update.zip, 421KB) downloaded from ms0365-support.login-verification.click/auth/drop/update.zip | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:46:41Z | OBSERVATION | WazuhEDR process telemetry | powershell.exe spawned on WST-WS-031 with base64-encoded command attempting to reach hxxps://ms0365-support[.]login-verification[.]click/auth, -ep bypass -w hidden flags | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:46:57Z | OBSERVATION | WazuhEDR process telemetry | MSBuild.exe spawned as child of powershell.exe, working directory C:\\Users\\dmarsh\\AppData\\Local\\Temp with argument C:\\Users\\dmarsh\\AppData\\Local\\Temp\\update.xml | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:47:02Z | OBSERVATION | WazuhEDR network telemetry | MSBuild.exe established outbound TCP connection to 185.220.101.47:443 (TOR exit relay, 22/91 VT detections, ASN AS208294 Foundation for Applied Privacy, Germany) | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:47:11Z | OBSERVATION | SIEM alert | WazuhEDR rule wz-edr-100041 fired: Suspicious process tree PowerShell → MSBuild with outbound C2 activity on clinical workstation | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:52:18Z | DECISION | Massimo, on-call SOC | Incident declared at SEV2: confirmed credential compromise (phishing 2026-04-13), confirmed malware execution and C2 beaconing from high-criticality clinical workstation (WST-WS-031). Data exfiltration not yet confirmed; clinical operations impact unknown. Escalating to IR Commander and initiating PB-CRED-001 Credential Exposure playbook. | source=alert A-20260414-9841 + proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:52:18Z | ACTION | Massimo, on-call SOC | Assigned incident IR-20260414-01 to James Chen as IR Commander; queued for immediate tier-2 analysis and containment planning | source=MedDefense-SOC-Splunk incident queue | certainty=confirmed
- 2026-04-14T03:14:18Z | EVIDENCE | SOC Evidence Collector | Incident evidence preservation complete: /evidence/IR-20260414-01/ contains all 9 artifact categories (memory, processes, network, telemetry, SIEM alert, proxy/DNS logs, auth logs, malware files); chain of custody manifest signed; all SHA-256 hashes verified (exit code 0) | source=/evidence/IR-20260414-01/hashes.txt | certainty=confirmed
- 2026-04-14T03:17:42Z | DECISION | James Chen, IR Commander | Containment strategy selected: Network isolation (Strategy A—move WST-WS-031 to quarantine VLAN 999, block outbound, allow IR jumpbox access only). Rationale: preserves volatile evidence, severs C2 immediately, remains fully reversible, and clinical impact bounded by 4 spare workstations at West Campus Lab. Strategy B (power-off) destroys memory; Strategy C (selective kill) risks persistence. Execution authorized for 2026-04-14T03:19:04Z. | source=containment_decision.md | certainty=confirmed
- 2026-04-14T03:19:04Z | ACTION | Taj Patel, Network Operations | Switchport reassignment: moved WST-WS-031 from VLAN 118 (clinical) to VLAN 999 (quarantine, 10.42.999.0/24) on switch ms-lab-sw-03 port 47. Host IP reassigned to 10.42.999.31. Confirmed unreachable from clinical network; reachable from jumpbox (10.42.1.50) only. | source=containment_execution.md | certainty=confirmed
- 2026-04-14T03:19:18Z | ACTION | Taj Patel, Network Operations | Firewall rule deployed: deny outbound TCP/UDP to 185.220.101.47 from 10.42.999.31 (WST-WS-031). Last C2 packet to attacker IP observed at 03:19:11Z (MSBuild beacon, 248 bytes). Zero subsequent packets to 185.220.101.47 after rule activation; TCP RST from firewall at 03:19:18Z. Rule mirrored to secondary firewall at 03:20:15Z. | source=containment_execution.md | certainty=confirmed
- 2026-04-14T03:20:02Z | ACTION | Maria Gonzalez, Endpoint Security | WazuhEDR containment flag SET on WST-WS-031; agent policy changed to QUARANTINE_ISOLATION mode. No outbound traffic permitted except to WazuhEDR agent server and IR jumpbox. Agent check-in confirmed at 03:20:01Z; status = CONTAINED. Network isolation enforced at endpoint level. | source=containment_execution.md | certainty=confirmed
- 2026-04-14T03:22:04Z | ACTION | Massimo, Incident Response | Isolation verification completed from multiple sources: (1) clinical VLAN ping = timeout, (2) jumpbox ping = success (4 ms), (3) netflow to 185.220.101.47 = zero packets for >2.5 min, (4) WazuhEDR agent = CONTAINED status. WST-WS-031 successfully isolated; C2 severed; forensic access via jumpbox confirmed active. | source=containment_execution.md | certainty=confirmed
- 2026-04-14T03:22:47Z | OBSERVATION | ad_dc01/ad_dc02 | TGS_REQ by dmarsh for cifs/WST-WS-017 and host/WST-WS-017 (03:22:48Z) from WST-WS-031, src_ip 10.42.118.31, result=success | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:23:01Z | OBSERVATION | ad_dc01/ad_dc02 | Kerberos network logon (type 3, 4624, logon_id 0x7a2d18) by dmarsh on WST-WS-017 from 10.42.118.31; SMB session to ADMIN$ at 03:23:02Z | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:23:44Z | OBSERVATION | WazuhEDR | WST-WS-017: powershell.exe (PID 4402, parent services.exe) -ep bypass -w hidden -enc, decodes to $s="https://91.234.99.107/z"; update.xml written 03:23:59Z with same SHA-256 as WST-WS-031 copy (a4f1e9b4…); MSBuild.exe (PID 5108) spawned 03:24:12Z | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:27:13Z | OBSERVATION | WazuhEDR | WST-WS-017 MSBuild.exe (PID 5108) established TCP 10.42.118.17:55401 -> 91.234.99.107:443; second C2 address | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:34:12Z | OBSERVATION | Massimo, on-call SOC | Expansion slice surfaced while reviewing preserved auth logs; consecutive TGS_REQ from a non-authorized source host indicates Pass-the-Ticket using dmarsh Kerberos material | source=auth_expansion_0334Z.log | certainty=high
- 2026-04-14T03:34:12Z | OBSERVATION | Massimo, on-call SOC | Containment gap: WST-WS-031 issued TGS_REQ from its clinical address 10.42.118.31 at 03:22:47Z, after the 03:19:04Z (VLAN 999 move) and 03:22:04Z (isolation verified) entries. Those entries' conclusion that WST-WS-031 was isolated is superseded; host retained domain controller reachability | source=auth_expansion_0334Z.log + entries 03:19:04Z, 03:22:04Z | certainty=confirmed
- 2026-04-14T03:34:12Z | EVIDENCE | Massimo, on-call SOC | auth_expansion_0334Z.log preserved; sha256=d0c2e66f8e417e7439b43119501945f76d78660774f1ee7e9cb91c725a2ffedc | source=/evidence/IR-2026-0414-01/authentication/auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:36:00Z | DECISION | James Chen, IR Commander | Scope expanded to WST-WS-017 and to any host holding dmarsh Kerberos tickets since 2026-04-13T18:14Z. Preserve evidence on WST-WS-017 before isolating it; block 91.234.99.107 at perimeter; revoke dmarsh Kerberos tickets and Azure AD sessions | source=entries 03:22:47Z–03:34:12Z | certainty=confirmed
- 2026-04-14T03:40:18Z | OBSERVATION | ad_dc01/ad_dc02 | TGS_REQ by dmarsh for cifs/LIS-WSIDE-01 from WST-WS-017 (10.42.118.17); repeated 03:41:52Z with ticket reuse | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:42:08Z | OBSERVATION | ad_dc01/ad_dc02 | Kerberos network logon (type 3, 4624, logon_id 0x91f204) by dmarsh on LIS-WSIDE-01 from 10.42.118.17 | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:43:30Z | OBSERVATION | LIS-WSIDE-01 Security log | PHI read: 14 PDFs under C:\LIS\reports\daily\ via LIS_REPORTS$ (4663, read), incl. MRN_redacted\2026-04-13_results.pdf (03:43:34Z) and 2026-04-13_microbio.pdf (03:43:41Z). Exfiltration not established from available data | source=auth_expansion_0334Z.log | certainty=confirmed
- 2026-04-14T03:45:00Z | DECISION | James Chen, IR Commander | Severity raised SEV2 -> SEV1, superseding 02:52:18Z declaration: PHI accessed on LIS-WSIDE-01 under attacker-controlled dmarsh identity; lateral movement across 3 hosts; second C2; WST-WS-031 containment bypassed. LIS-WSIDE-01 added to scope | source=entries 03:22:47Z–03:43:30Z | certainty=confirmed
- 2026-04-14T03:45:00Z | DECISION | James Chen, IR Commander | krbtgt double reset required (supersedes conditional ERAD-013) given Pass-the-Ticket indication; HIPAA breach risk assessment opened, owned by Privacy Officer with General Counsel | source=entry 03:34:12Z + 03:43:30Z | certainty=high
- 2026-04-14T03:50:00Z | COMMUNICATION | James Chen, IR Commander | SEV1 escalation sent to CISO, General Counsel, Privacy Officer, Executive sponsor; template TPL-SEV1-ESCALATION | source=incident channel | certainty=confirmed
- 2026-04-14T10:12:00Z | OBSERVATION | Endpoint API | WST-WS-031 rebuilt from clean baseline image | source=mock_validation_api/endpoint/processtree/WST-WS-031.json | certainty=confirmed
- 2026-04-14T11:04:00Z | OBSERVATION | Endpoint API | WST-WS-017 rebuilt from clean baseline image; LIS-WSIDE-01 not rebuilt (no attacker process lineage post-containment) | source=mock_validation_api/endpoint/processtree/WST-WS-017.json, LIS-WSIDE-01.json | certainty=confirmed
- 2026-04-14T14:22:10Z | OBSERVATION | SIEM | 24h netflow: zero packets to 185.220.101.47 and 91.234.99.107, egress deny verified for both; wz-edr-100041 synthetic hit on SOC-TEST-001 (MTTD 4 s) | source=mock_validation_api/siem/netflow.json, siem/detection/wz-edr-100041/synthetic.json | certainty=confirmed
- 2026-04-14T14:25:00Z | ACTION | Massimo, on-call SOC | recovery_validation.sh executed: 6/6 PASS, exit 0 | source=recovery_validation.sh output | certainty=confirmed
- 2026-04-14T14:30:00Z | COMMUNICATION | James Chen, IR Commander | Recovery status update to CISO, General Counsel, Privacy Officer, Executive sponsor, West Campus Lab manager: services restored, validation passed, incident remains open for regulatory assessment; template TPL-STATUS-UPDATE | source=incident channel | certainty=confirmed
- 2026-04-14T14:35:00Z | ACTION | Massimo, Scribe | Incident ID normalized to IR-2026-0414-01 to match evidence store; earlier artifacts using IR-20260414-01 refer to this incident. Handoff package incident_handoff.md issued | source=incident_handoff.md | certainty=confirmed

## 5. Decisions

Options, trade-offs, approval and rollback: `containment_decision.md`.

| Time | By | Decision |
|---|---|---|
| 02:52:18Z | Massimo | Declare SEV2; run PB-CRED-001 |
| 03:17:42Z | James Chen | Containment Strategy A (quarantine VLAN) for WST-WS-031: keeps volatile evidence, reversible. Found incomplete at 03:34:12Z |
| 03:36:00Z | James Chen | Expand scope to WST-WS-017 and dmarsh ticket holders; block 91.234.99.107; revoke dmarsh tickets and sessions |
| 03:45:00Z | James Chen | SEV2 → SEV1 (PHI accessed); add LIS-WSIDE-01 |
| 03:45:00Z | James Chen | krbtgt double reset mandatory; open HIPAA assessment |

## 6. Evidence Index

Store `/evidence/IR-2026-0414-01/`, manifest `hashes.txt`, SHA-256. Re-verification (`sha256sum -c`) at 14:25Z: 5/5 OK.

| Artifact | Path | SHA-256 |
|---|---|---|
| SIEM alert A-20260414-9841 | siem/alert_A-20260414-9841.json | 535f02ef55927decc138e5542ad825dea3754a7370c6ee05f58f7d8480eaf6db |
| EDR telemetry WST-WS-031 (24 h) | endpoint_telemetry/edr_wst_ws_031_24h.jsonl | f7e404df7556b47bb97f08d10746cad73db374622c4d84035ce23317a8a6c325 |
| Proxy log dmarsh (24 h) | proxy_dns/proxy_24h_dmarsh.log | 7738cd69ce3c726273fa6ca1a3eac54bef3d22b63859af071a203cb90b80f303 |
| Auth log dmarsh, AD + Azure AD (24 h) | authentication/auth_24h_dmarsh.json | 398aae6da40893af8c41da489b875c96e1cb74d9d3c5a6485645811031a92ced |
| Scope expansion slice | authentication/auth_expansion_0334Z.log | d0c2e66f8e417e7439b43119501945f76d78660774f1ee7e9cb91c725a2ffedc |
| Memory, process list, connections, DNS (WST-WS-031) | memory/, process_tree/, network/, proxy_dns/ | Not in lab materials: use production hashes.txt |
| update.zip / update.exe / update.xml | malware/ | EDR-reported: 3c2a1b9e…3c2b1a / 5a4b3c2d…6f5a4b / a4f1e9b4…b1c2d3 |

Gap: no volatile capture recorded for WST-WS-017 or LIS-WSIDE-01 (§9 #7).

## 7. Eradication Status

`eradication_checklist.yaml`: **0 complete, 2 in progress (ERAD-014, ERAD-016), 16 pending** of 18. Out of date: no items for WST-WS-017 or LIS-WSIDE-01; ERAD-013 (krbtgt) still conditional; ERAD-015 pending although egress deny is verified; rebuilds not recorded (§9 #6).

## 8. Recovery Status

`./recovery_validation.sh http://127.0.0.1:8080 /evidence/IR-2026-0414-01` (mock validation API), exit 0:

```
[PASS] process tree: no powershell->msbuild in last 24h
[PASS] netflow: no outbound to C2 IPs in last 24h
[PASS] persistence: no artifacts found
[PASS] service health: epic and lis respond 200
[PASS] detection: wz-edr-100041 active
[PASS] evidence hashes: all artifacts match SHA-256
ALL CHECKS PASSED
```

The script does not check Run keys; a manual API query shows them empty on all 3 hosts (§9 #8).

## 9. Outstanding Items

| # | Item | Owner | Deadline |
|---|---|---|---|
| 1 | HIPAA four-factor risk assessment and notification decision | Privacy Officer + General Counsel | 2026-04-21 (notice ≤ 2026-06-13) |
| 2 | Determine whether PHI left the network (LIS-WSIDE-01 / WST-WS-017 egress from 03:42Z) | Massimo | 2026-04-15T12:00Z |
| 3 | dmarsh password reset ×2, Kerberos purge, Azure AD token revoke (decided, execution not recorded) | Identity team | 2026-04-14T16:00Z |
| 4 | krbtgt double reset; rotate 3 machine accounts; hunt dmarsh ticket holders (4769/4624) | AD team (CISO approval) / Massimo | 2026-04-15 |
| 5 | Record WST-WS-031 isolation deviation and root cause in containment_execution.md | Taj Patel, Network Ops | 2026-04-15 |
| 6 | Update eradication_checklist.yaml (§7) | Massimo | 2026-04-15 |
| 7 | Confirm WST-WS-017 pre-rebuild capture; forensic image LIS-WSIDE-01 under legal hold | Maria Gonzalez, Endpoint Security | 2026-04-15 |
| 8 | Add Run-key check to recovery_validation.sh; rerun | Massimo | 2026-04-16 |
| 9 | Block phishing domain; purge lure email; legal hold on evidence | SOC / General Counsel | 2026-04-15 |
| 10 | Post-incident review | James Chen | 2026-04-28 |

## 10. Regulatory Posture

HIPAA breach notification assessment **is triggered**: an attacker using dmarsh's identity read 14 LIS patient report PDFs at 03:43:30Z. Under 45 CFR 164.402 this is presumed a breach unless a documented four-factor risk assessment shows a low probability of compromise. Exfiltration is not established, but an active C2 channel means acquisition cannot be ruled out, and no encryption safe harbor applies. **Owner: Privacy Officer, with General Counsel**; the IR Commander supplies evidence. Discovery was 2026-04-14, so individual notice is due no later than 2026-06-13. HHS and media duties depend on the patient count (≥ 500 triggers immediate notice), which is still unknown.

## 11. Communications Log

| Time | From → Audience | Template | Content |
|---|---|---|---|
| 02:52:18Z | Massimo → James Chen | SIEM queue assignment | SEV2 declared, assigned |
| 03:50:00Z | James Chen → CISO, General Counsel, Privacy Officer, Executive sponsor | TPL-SEV1-ESCALATION | SEV1: lateral movement, PHI accessed, containment gap |
| 14:30:00Z | James Chen → same + West Campus Lab manager | TPL-STATUS-UPDATE | Services restored, validation passed, incident open |

Gap: no update is recorded between 02:52Z and 03:50Z, and no lab notice is recorded before WST-WS-031 was isolated.
