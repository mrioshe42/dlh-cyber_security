# IR Activation: IR-2026-0420-01

## Incident Declaration Header

- **incident_id:** IR-2026-0420-01
- **declared_at:** 2026-04-20T19:52:00Z
- **declared_by:** massimo, On-call IR
- **initial_severity:** SEV2


## Severity Reasoning

**SEV2 — Malware confirmed on multiple clinical workstations**

Evidence:
- Wazuh EDR alert (rule `wz-edr-200214`) fired on service installation across 3 clinical workstations at Main Hospital (CS-WS-104, CS-WS-107, CS-WS-112) within a 12-minute window
- Suspicious service `WinHealthSvc` installed with image path `C:\ProgramData\Microsoft\svchost32.exe` — not a legitimate Microsoft binary or path
- Fourth workstation (CS-WS-101 at ED charge desk) experiencing system degradation and file modification ("filenames look different")
- All workstations are clinical-access points; potential for Epic/LIS access

Severity classification per MedDefense matrix:
- "Malware confirmed on a single clinical workstation at West Campus, Main Hospital, or North Site" triggers SEV2
- Four workstations affected elevates the operational impact
- No confirmed exfiltration yet; escalation path to SEV1 if lateral movement or data access is confirmed

## Playbook Activated

- **Playbook:** Clinical Workstation Malware Response
- **Justification:** Multiple clinical workstations at Main Hospital showing signs of malicious service installation and system degradation. Requires rapid triage to confirm spread, assess Epic/LIS access risk, and execute containment strategy before lateral movement to infrastructure servers (particularly SCHED-SVR-01, which is already showing 90+ minutes of unusual disk activity).

## Initial Notifications (first 15 minutes)

- **19:52:00Z** — On-call IR declared incident and initiated activation
- **19:52:30Z** — IR Commander paged (routing: on-call SOC lead or IR manager)
- **19:53:00Z** — Scribe assigned to timeline and evidence preservation
- **19:54:15Z** — Network Operations notified: hold on any isolation pending containment strategy approval
- **19:55:30Z** — Endpoint Security team notified: prepare for potential evidence collection across CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112
- **19:56:45Z** — Clinical Operations lead paged: potential impact to ED workstations; on-call nurse on CS-WS-101 instructed to stop work and leave console unattended

## Initial Communication

**TO:** On-call Clinical Operations Lead (ED Charge Nurse at Main Hospital)  
**FROM:** On-call IR  
**TIME:** 2026-04-20T19:52:00Z  
**SUBJECT:** Clinical Workstation Security Incident — ED Charge Desk Workstation

An incident has been declared affecting clinical workstations at Main Hospital. We have detected suspicious software installation on multiple clinical systems, including the ED charge desk workstation where your staff are working. Out of an abundance of caution and to protect patient data, we are asking the on-call nurse to immediately stop work on CS-WS-101, leave the console unattended, and use a backup workstation if available. This is a precautionary measure; we are investigating and will provide updates every 15 minutes. We will contact you if clinical operations impact is necessary. Please confirm receipt and that your team has moved to a safe workstation.

## Evidence Snapshot at Activation

- Memory dump of CS-WS-101 acquired by Torres at **19:38:18Z** using WinPmem, written to `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` at 19:41Z
  - **NOTE:** No hash computed at acquisition (known issue from IR-2026-0414-01; hash must be computed during evidence preservation step)
- SIEM alert rule `wz-edr-200214` (service installation) fired at approximately **19:44Z** on hosts CS-WS-104, CS-WS-107, CS-WS-112 (within 12-minute window)
- Scheduling server SCHED-SVR-01 showing sustained high disk I/O and CPU utilization for 90+ minutes (pre-incident baseline unknown; requires triage)
- No network isolation applied yet; all workstations remain on clinical network
- No hosts have been power-cycled or rebooted

## Critical Gaps for IR Commander

1. **Spread determination:** Scope is limited to 4 workstations; need to confirm via SIEM/EDR whether lateral movement has occurred to other clinical systems or infrastructure (particularly SCHED-SVR-01 and Epic/LIS servers)
2. **Patient data exposure:** Unknown whether the suspicious service has accessed Epic, LIS-WSIDE-01, or file server shares; requires network telemetry and process telemetry triage
3. **Malware attribution:** Service binary not yet acquired; cannot determine if this is a known family or activity group
4. **Containment strategy:** Decision pending on network isolation vs. continued monitoring pending triage completion
