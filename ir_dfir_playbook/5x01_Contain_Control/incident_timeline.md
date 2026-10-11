# Incident Timeline: IR-20260414-01

## Header

- incident_id: IR-20260414-01
- declared_at: 2026-04-14T02:52:18Z
- declared_by: Massimo, on-call SOC
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Massimo

## Legend

- OBSERVATION: Raw fact from an alert, log, or artifact
- DECISION: A choice made by an authorized actor, with rationale
- ACTION: An operation executed against an asset, with owner
- COMMUNICATION: A message sent or received, with audience
- EVIDENCE: A preserved artifact with hash and storage path

## Entries

- 2026-04-13T18:14:02Z | OBSERVATION | SIEM proxy event | User dmarsh visited ms0365-support.login-verification.click/auth (phishing mimicry domain) via email referrer | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | SIEM proxy event | POST credentials submitted to malicious domain ms0365-support.login-verification.click/auth/submit returning 302 redirect | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | SIEM proxy event | Malware binary (update.zip, 421KB) downloaded from ms0365-support.login-verification.click/auth/drop/update.zip | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | WazuhEDR process telemetry | powershell.exe spawned on WST-WS-031 with base64-encoded command attempting to reach hxxps://ms0365-support[.]login-verification[.]click/auth, -ep bypass -w hidden flags | source=alert A-20260414-9841 | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | WazuhEDR process telemetry | MSBuild.exe spawned as child of powershell.exe, working directory C:\\Users\\dmarsh\\AppData\\Local\\Temp with argument C:\\Users\\dmarsh\\AppData\\Local\\Temp\\update.xml | source=alert A-20260414-9841 | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | WazuhEDR network telemetry | MSBuild.exe established outbound TCP connection to 185.220.101.47:443 (TOR exit relay, 22/91 VT detections, ASN AS208294 Foundation for Applied Privacy, Germany) | source=alert A-20260414-9841 | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM alert | WazuhEDR rule wz-edr-100041 fired: Suspicious process tree PowerShell → MSBuild with outbound C2 activity on clinical workstation | source=alert A-20260414-9841 | certainty=confirmed

- 2026-04-14T02:52:18Z | DECISION | Massimo, on-call SOC | Incident declared at SEV2: confirmed credential compromise (phishing 2026-04-13), confirmed malware execution and C2 beaconing from high-criticality clinical workstation (WST-WS-031). Data exfiltration not yet confirmed; clinical operations impact unknown. Escalating to IR Commander and initiating PB-CRED-001 Credential Exposure playbook. | source=alert A-20260414-9841 + proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:52:18Z | ACTION | Massimo, on-call SOC | Assigned incident IR-20260414-01 to James Chen as IR Commander; queued for immediate tier-2 analysis and containment planning | source=MedDefense-SOC-Splunk incident queue | certainty=confirmed
