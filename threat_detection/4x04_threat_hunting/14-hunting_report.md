# Threat Hunting Report

| | |
|---|---|
| **Organization** | MedDefense Health Systems |
| **Prepared for** | James Chen (SOC Lead); Dr. Patricia Morales (board briefing) |
| **Classification** | TLP:AMBER |
| **Hunt window** | 2026-05-04 to 2026-05-18 (14 days, 6,544 unique events, 28 agents) |
| **Intelligence basis** | HC3-2026-HEALTHBANE-004 |
| **Verdict** | **Stage 4 happened. Confidence: HIGH.** |

## 1. Executive Summary

**What we hunted and why.** The federal health-sector advisory (HC3) described a fourth stage of the HEALTHBANE campaign in which attackers move between servers using only tools already built into Windows, so antivirus and blocklists cannot see it. Our earlier ATT&CK map showed we could confirm only 16 of the 29 techniques this campaign uses (55%). The gap included exactly the techniques Stage 4 relies on, so we hunted that gap directly instead of waiting for an alert.

**Key finding.** Yes, Stage 4 happened here. Between 5 and 13 May an attacker took control of one records workstation (`WS-RECV-03`), stole the password material of a service account (`svc_healthsync`) from the machine's memory, and used it to reach three servers, one of them the domain controller. None of this triggered an alert. Every event was recorded in our logs, but we had no rule looking for it.

**Impact assessment.**

| System reached | What it holds | Attacker activity observed |
|---|---|---|
| **SRV-HEALTH-DB** (6 May) | Patient health records (the service account has read/write) | Remote command execution, directory listing of the backup folder, service enumeration, a script copied onto the server |
| **SRV-INS-DB** (9 May) | Insurance claims and policies | Same pattern, claims folder listed |
| **SRV-DC-01** (13 May) | The domain's identity directory | Remote command execution, then a query listing every enabled user account |

Patient and claims data was **potentially exposed**. The logs show the attacker could read and list it. They do not show data leaving the network, because this hunt did not cover exfiltration (see section 7). Treat as a possible HIPAA-reportable event until incident response says otherwise. The attacker was inside for **7 days 22 hours** before this hunt found them.

**Remediation status.**
- Four detection-rule drafts and one network-rule draft are written (`detection_rules/`). **They are drafts, not yet deployed.** Deployment is the first action below.
- Confirmed ATT&CK coverage rose from **55% (16/29) to 76% (22/29)**, close to the 80% goal. The remaining 24% is listed honestly in section 7.
- Immediate containment of `WS-RECV-03` and rotation of `svc_healthsync` are still open.

**Decisions needed from the board:** approve emergency containment and credential rotation, authorize an incident-response engagement, and fund recurring threat hunting (section 8).

## 2. Hunt Methodology

**Hypothesis-driven, in four steps.**

1. **Intelligence.** The HC3 advisory gives the Stage 4 playbook: PsExec, WMI, PowerShell Remoting, LSASS credential theft, service-account abuse, all done off-hours.
2. **Gap analysis.** We mapped those techniques to our ATT&CK coverage. Five were not covered: T1021.002, T1047, T1021.006, T1003.001, T1078.002. These became hypotheses H1 to H5 and were ranked P1 (PsExec, LSASS) down to P5 (domain accounts).
3. **Baseline.** Before hunting we profiled legitimate administration so we would not flag normal work.
4. **Targeted queries.** One hunt per hypothesis, then correlation across all of them.

**Data sources.**

| Source | Content | Note |
|---|---|---|
| `wazuh_alerts_14d.json` | 6,544 events: Windows logons (4624), Sysmon process, network, registry, file, DNS and process-access events | Primary |
| `wazuh_raw_sysmon_14d.json` | 3,256 raw Sysmon events | A subset of the alerts file, de-duplicated by event ID |
| `robert_kim_activity.json` | 93 known-legitimate admin events | Baseline |
| `admin_schedule.txt`, `service_accounts.txt`, `network_topology.txt` | Documented maintenance windows, service-account authorization matrix, network layout | False-positive controls |

**Baseline (Robert Kim, the only IT administrator).** 44 PsExec, 31 WMI and 18 PowerShell Remoting events. All come from `WS-ADMIN-01`, all use `MEDDEFENSE\robert.kim`, all fall between 08:00 and 18:00 Central, and none use a service account. Activity peaks on Tuesday (software deployment) and Thursday (patching) and never occurs on weekends. Timestamps in the logs are UTC. We converted them to Central (UTC-5) before comparing, otherwise normal work would look like night activity.

**Anomaly criteria** used in every hunt: a tool run from any host other than `WS-ADMIN-01`; use outside business hours or on a weekend; a service account used from a workstation; any account other than `robert.kim` using admin tools.

## 3. Findings per Hypothesis

| # | Hypothesis | Status | Confidence |
|---|---|---|---|
| H1 | PsExec lateral movement (T1021.002) | **POSITIVE** | HIGH |
| H2 | LSASS credential access (T1003.001) | **POSITIVE** | HIGH |
| H3 | WMI remote execution (T1047) | **POSITIVE** | HIGH |
| H4 | PowerShell Remoting (T1021.006) | **POSITIVE** | HIGH |
| H5 | Service account abuse (T1078.002) | **POSITIVE** | CRITICAL |

**H1 — PsExec.** 50 PsExec events in 14 days; 44 match the baseline. The other 6 (three process starts and three matching SMB connections to port 445) all come from `WS-RECV-03`, run `C:\Users\Public\Downloads\PsExec64.exe` (the baseline uses only `C:\Tools\Sysinternals`), and ran at 02:14, 03:42 and 01:58 Central. One was on a Saturday. Targets were SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01, using `svc_healthsync`. Every anomaly flag is tripped: wrong source host, off-hours, service account, database or domain-controller target, and a non-baseline binary path.

**H2 — LSASS.** 12 events opened the Windows credential store (`lsass.exe`). 10 came from standard system processes in System32. 2 came from `C:\Windows\Temp\debug_tool.exe`, run as `MEDDEFENSE\records03`, with access mask `0x1010` (memory read). This is the exact binary path and access pattern HC3 describes. The tool ran with `-p 648 -o out.dat`, and an output file was created three seconds later. The dumps happened on 5 May and again on 12 May, the day before the domain-controller step.

**H3 — WMI.** 5 events where `WmiPrvSE.exe` spawned `cmd.exe` or `powershell.exe` as `svc_healthsync` on SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01. Commands were `dir` of the backup and claims folders, `sc query` of services, and `Get-ADUser -Filter *` on the domain controller. There is no legitimate baseline for this pattern on these servers.

**H4 — PowerShell Remoting.** 4 events: `Enter-PSSession` from `WS-RECV-03` to SRV-HEALTH-DB and SRV-INS-DB, each followed within minutes by a `Copy-Item` that pulled `sync_healthdata.ps1` from the workstation onto the server as `stage1.ps1`. Matches the advisory's "staging within 5 minutes of session" behavior.

**H5 — Service account.** `svc_healthsync` is authorized only on SRV-HEALTH-DB (service logon, Kerberos). Of 846 of its logons, 840 comply. The other 6 are NTLM logons from `WS-RECV-03`, which is a double violation: workstation source and NTLM, which the matrix says indicates credential theft. Combined with H1, H2 and H4 on the same host, this is the strongest single indicator.

**Why these are not false positives.** The only legitimate admin traffic in the data comes from `WS-ADMIN-01` as `robert.kim` inside business hours. None of the findings above shares host, account, time window or binary path with it.

## 4. Reconstructed Attack Timeline

Times are UTC (Central = UTC-5). Pivot host `WS-RECV-03`; stolen credential `svc_healthsync`.

| Date (UTC) | Phase | Event |
|---|---|---|
| **5 May 08:22** (03:22 CDT) | Credential access | `debug_tool.exe` runs, reads LSASS memory, writes `out.dat` |
| **6 May 07:14** (02:14 CDT) | Lateral movement | `svc_healthsync` NTLM logon `WS-RECV-03` → SRV-HEALTH-DB; PsExec to the same server |
| 6 May 07:31–07:33 | Reconnaissance | WMI: backup-folder listing, service query |
| 6 May 07:48–07:52 | Lateral movement, staging | PSRemoting session; `Copy-Item` of `sync_healthdata.ps1` |
| **9 May 08:42** (03:42 CDT, Saturday) | Expansion | NTLM logon to SRV-INS-DB; PsExec |
| 9 May 08:55–08:57 | Reconnaissance | WMI: claims-folder listing, service query |
| 9 May 09:15–09:19 | Lateral movement, staging | PSRemoting session; `Copy-Item` of the script |
| **12 May 07:45** | Credential access | Second LSASS dump, `out2.dat` (credential refresh) |
| **13 May 06:58** (01:58 CDT) | Expansion | NTLM logon to **SRV-DC-01**; PsExec running `powershell.exe` |
| 13 May 07:12 | Reconnaissance | WMI `Get-ADUser -Filter *` on the domain controller |

**Narrative.** After an initial foothold on a records workstation, the attacker dumped LSASS memory to obtain the service account's credentials. A day later, in the middle of the night, they used it to reach the patient-records server and ran the full Stage 4 sequence: PsExec to execute, WMI to survey, PSRemoting to stage a script. Three days later the same pattern ran against the claims server. After refreshing credentials with a second dump, they repeated it against the domain controller, where they listed all domain users.

**Dwell time: 7 days 22 hours** (5 May 08:22 to 13 May 07:12 UTC). The sequence of a first-night credential dump, bursts of lateral movement separated by dormant days, and a credential refresh before the domain controller matches the operational pattern in the HC3 advisory.

## 5. ATT&CK Update

**Coverage, confirmed (observed in telemetry) techniques out of the 29-technique HEALTHBANE threat model:**

```
Before hunt 16/29   55%
After hunt  22/29   76%
                                      +6 techniques confirmed
```

**New techniques discovered (confirmed by hunt evidence):**

| Technique | Tactic | Evidence |
|---|---|---|
| T1003.001 LSASS Memory | Credential access | `debug_tool.exe`, mask `0x1010`, 2 dumps |
| T1021.002 SMB / Windows Admin Shares (PsExec) | Lateral movement | 3 sessions, 3 servers |
| T1047 Windows Management Instrumentation | Execution | 5 remote WMI commands |
| T1021.006 Windows Remote Management (PSRemoting) | Lateral movement | 2 sessions with file staging |
| T1078.002 Valid Accounts: Domain Accounts | Defense evasion | `svc_healthsync` misuse, 6 logons |
| T1550.002 Alternate Authentication Material (NTLM, pass-the-hash style) | Lateral movement | NTLM-only logons by a Kerberos-only account |

Three of these (T1021.002, T1047, T1021.006) were previously listed as "campaign-possible, unconfirmed". They are now confirmed attacker behavior at MedDefense.

## 6. Detection Improvements

Rule drafts are in `detection_rules/hunt_rules.xml` and `detection_rules/network.rules`. Each was replayed over the 14-day data and the admin baseline. **None fires on any baseline event.**

| Rule | Detects | Fires in 14d data | Expected false positives |
|---|---|---|---|
| 100100 | PsExec from a host other than `WS-ADMIN-01` | 6 | VERY LOW |
| 100101 | `lsass.exe` opened by a process outside the System32 allowlist | 2 | LOW (new security tools may need allowlisting) |
| 100102 | Service account logon with a workstation source | 6 | VERY LOW |
| 100103 | `WmiPrvSE.exe` spawning `cmd.exe` / `powershell.exe` | 5 | MEDIUM (admin WMI inventory must be allowlisted by user and host) |
| 9000030 | Network: PsExec service-install pattern over SMB (port 445) from a non-admin host | 3 | VERY LOW |

**Gap closure (from the gap analysis).** All six gaps had the same root cause: the data was in the logs, but only generic low-severity rules (level 3–5) matched it, and the only custom rule fires on phishing indicators. Four gaps are now closed by draft rules above. The service-account rule also covers the NTLM gap (same events). **PowerShell Remoting is only partly closed**: we need a rule (not yet drafted) and PowerShell script-block logging, which is absent from the export (zero 4103/4104 events).

**Coverage statistics.** Observed coverage is 55% → 76%. Techniques with a deployable detection rule: 4 techniques plus the network rule (T1021.002 is covered twice). All of that is still pending deployment.

## 7. Remaining Gaps and Recommendations

**What is still unknown (the 24% not confirmed):**

| Technique(s) | Status | Why we cannot say it did not happen |
|---|---|---|
| T1053.005 Scheduled Task persistence | Not covered | The advisory describes persistence on night 5. The export contains no task-creation events (4698), so we cannot rule it in or out |
| T1074.001 / T1560.001 Data staging and archiving | Not covered | We saw a script copied in, but no archive-creation events. HC3 saw data pulled back out at one victim |
| T1070.001 Log tampering | Not covered | HC3 victims had selective log deletion. Detecting it needs raw log inspection, which we did not do |
| T1041 / T1048.003 / T1005 Exfiltration, collection | Inferred only | This hunt did not look for data leaving the network. **Whether patient data actually left is unknown** |
| T1078 General valid accounts | Inferred | Initial access path to `WS-RECV-03` (the `records03` account) is not established |

**Immediate (0–48 hours): incident response for `WS-RECV-03` (bridge to Module 5).**
1. Isolate `WS-RECV-03` from the network; capture memory first, then a disk image.
2. Recover and analyze `C:\Windows\Temp\debug_tool.exe`, `out.dat` / `out2.dat`, `C:\Users\Public\Downloads\PsExec64.exe` and `sync_healthdata.ps1`; remove `stage1.ps1` from SRV-HEALTH-DB and SRV-INS-DB.
3. Disable and reset `svc_healthsync` and the `records03` account. Because the attacker reached the domain controller, treat all credentials that have touched `WS-RECV-03` as compromised and plan a `krbtgt` double-reset.
4. Deploy rules 100100–100103 and 9000030 and watch for recurrence. Hunt SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01 for persistence and exfiltration.
5. Involve the CISO and privacy officer to start the breach-assessment clock for patient data.

**Short term (1–4 weeks).**
- **Rotate every service account** with database-server access, using managed accounts (gMSA) so no human knows the password; enforce "authenticate only from the service host".
- **Privileged access review.** The matrix says `svc_healthsync` has no privileges on SRV-DC-01 or SRV-INS-DB, yet commands ran under it on both. Either the matrix is wrong or the permissions drifted. Find out which.
- Draft and deploy the two missing rules (PowerShell Remoting, NTLM by service accounts); enable PowerShell script-block logging (4103/4104) and scheduled-task auditing (4698).
- Block NTLM for service accounts; restrict PsExec and WMI to `WS-ADMIN-01`.

**Medium term (1–3 months).**
- Full Sysmon deployment (Events 1, 3, 10, 11, 12/13) on every endpoint and server, with a managed configuration.
- Behavioral analytics: baseline-versus-actual comparison for admin tools, service-account logons and LSASS access, so rules adapt instead of depending on hand-written allowlists.
- Recurring hunts for the unconfirmed techniques above, starting with persistence and exfiltration.

## 8. Lessons Learned

**Why 55% coverage created a false sense of security.** The 16 techniques we could see were the early, noisy ones: phishing, the dropper, command-and-control. The 13 we could not see were the quiet ones, and Stage 4 lives there. A coverage number says how many techniques we have mapped, not how much of the attack we would catch. Our dashboards looked reasonable while an attacker spent eight days inside, and not one alert fired on the whole Stage 4 chain.

**Why reactive detection alone is insufficient against LOLBin attacks.** The attacker used no malware. PsExec, WMI and PowerShell are signed Microsoft tools that our own administrator uses weekly, so nothing is malicious by name or by hash. What is abnormal is context: which host, which account, what hour. Only a rule built on a known baseline, or a person asking "who else uses this?", can tell the two apart. Every one of these events was already in the logs. They looked ordinary because nobody had defined ordinary.

**Why proactive hunting must be a recurring discipline.** The hunt cycle is *hunt → find → detect → hunt again*. This hunt found an intrusion that automation could not, then converted each finding into a rule so the next occurrence alerts automatically. But rules only catch what we already know to look for. The 24% still unconfirmed is the next hunt's starting point. Run it on a regular schedule, seed each cycle from new threat intelligence, and keep the administrator baseline current. Otherwise the baseline decays and the false-positive controls stop working.
