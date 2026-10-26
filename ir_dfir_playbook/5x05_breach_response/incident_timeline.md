# Incident Timeline: IR-2026-0420-01

## Header

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52:00Z
- declared_by: massimo, On-call IR
- initial_severity: SEV2
- current_severity: SEV2

## Legend

- OBSERVATION: Raw fact from an alert, log, or artifact
- DECISION: A choice made by an authorized actor, with rationale
- ACTION: An operation executed against an asset, with owner
- COMMUNICATION: A message sent or received, with audience
- EVIDENCE: A preserved artifact with hash and storage path

## Entries

- 2026-04-20T19:23Z (approx) | OBSERVATION | Clinical staff report (via on-call nurse to Torres) | Workstation CS-WS-101 (ED charge desk) is "crawling", unresponsive, file names on desktop have changed; system degradation suspected | source=torres_call_transcript.md 19:43:22Z | certainty=confirmed

- 2026-04-20T19:23Z (approx, 90 min prior) | OBSERVATION | Network performance alert | SCHED-SVR-01 (scheduling server at Main Hospital) exhibiting sustained high CPU and disk queue depth for approximately 90 minutes prior to Torres call; pattern unfamiliar to operator, suspected runaway process or batch job | source=torres_call_transcript.md 19:43:50Z | certainty=confirmed

- 2026-04-20T19:44Z | OBSERVATION | Wazuh EDR alert fired | Rule ID wz-edr-200214 (service installation detection) triggered on three clinical workstations: CS-WS-104, CS-WS-107, CS-WS-112; all located at Main Hospital clinical areas; service installed within 12-minute window; service name `WinHealthSvc` with image path `C:\ProgramData\Microsoft\svchost32.exe` (non-Microsoft path and naming) | source=torres_call_transcript.md 19:44:20Z, alert rule wz-edr-200214 | certainty=confirmed

- 2026-04-20T19:38Z | EVIDENCE | Torres, Network Engineer | Memory dump of CS-WS-101 captured using WinPmem; written to `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` at 19:41Z | source=torres_call_transcript.md notes 19:41Z acquisition, handoff 19:52Z | certainty=confirmed

- 2026-04-20T19:52:00Z | DECISION | On-call IR (student) | Incident declared at SEV2: confirmed malware installation (suspicious service WinHealthSvc on 3 clinical workstations via SIEM alert wz-edr-200214) plus system degradation on 4th workstation (CS-WS-101). Scope: 4 clinical workstations at Main Hospital. Data exfiltration not yet confirmed; lateral movement to infrastructure or Epic/LIS not yet confirmed. Playbook activated: Clinical Workstation Malware Response. SEV2 justified per MedDefense severity matrix (malware confirmed on clinical workstations); escalation path to SEV1 if lateral movement or exfiltration confirmed. | source=torres_call_transcript.md + SIEM alert wz-edr-200214 | certainty=confirmed

- 2026-04-20T19:52:30Z | COMMUNICATION | On-call IR (student) | IR Commander paged via emergency routing for incident IR-2026-0420-01 SEV2 clinical workstation malware. Called with initial facts: 4 workstations affected, suspicious service, no isolation yet. | source=incident activation | certainty=confirmed

- 2026-04-20T19:56:45Z | COMMUNICATION | On-call IR (student) | Clinical Operations lead notified of incident scope and request to stop work on CS-WS-101. On-call nurse at ED charge desk instructed to leave workstation unattended and relocate to backup if available. | source=ir_activation.md | certainty=confirmed
