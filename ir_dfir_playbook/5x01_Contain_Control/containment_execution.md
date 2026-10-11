# Containment Execution: IR-20260414-01

**Strategy**: Network Isolation (VLAN 999 quarantine + egress block)  
**Execution Window**: 2026-04-14T03:19:04Z – 2026-04-14T03:25:30Z  
**Authorized by**: James Chen, IR Commander (approval timestamp: 2026-04-14T03:17:00Z)

## Execution Log

| Timestamp | Actor | Action | Expected Result | Observed Result | Deviation |
|-----------|-------|--------|-----------------|-----------------|-----------|
| 2026-04-14T03:19:04Z | Network Operations (Taj Patel) | Switchport reassignment: move WST-WS-031 (port 47, switch ms-lab-sw-03) from VLAN 118 (clinical) to VLAN 999 (quarantine) | Host loses network path to clinical network; reachable only via jumpbox (10.42.1.50) | Verified: VLAN membership changed in switch config; ARP entry shows 10.42.999.31 (new VLAN). Ping from clinical VLAN (10.42.118.0/24) times out; ping from jumpbox succeeds. | None |
| 2026-04-14T03:19:18Z | Network Operations (Taj Patel) | Firewall rule creation: deny outbound TCP/UDP to 185.220.101.47 from 10.42.999.31 (WST-WS-031) | No new netflow records to 185.220.101.47 after rule activation; existing connection terminates within 10 sec | Netflow confirmed zero packets to 185.220.101.47 from 03:19:18Z onward. Last packet to 185.220.101.47:443 at 2026-04-14T03:19:11Z (MSBuild C2 beacon, 248 bytes). TCP RST packets observed from firewall at 03:19:18Z. | None |
| 2026-04-14T03:20:02Z | Endpoint Security (Maria Gonzalez) | WazuhEDR containment flag SET on WST-WS-031 via agent console (QUARANTINE mode: no outbound except to agent server and IR jumpbox) | Endpoint policy applied; running processes and file activity logged but not blocked; network isolation enforced at agent level | Verified in WazuhEDR console: agent status = CONTAINED, policy = QUARANTINE_ISOLATION, last check-in 03:20:01Z. Agent confirmed firewall egress block is in effect. | None |
| 2026-04-14T03:21:30Z | Incident Response (Massimo) | SSH session established to WST-WS-031 from IR jumpbox (10.42.1.50) for forensic access | Session connects successfully; analyst tooling available for memory analysis and log collection | SSH connection successful (port 22, WazuhEDR agent permits jumpbox traffic). Remote PowerShell session active. Confirmed: analyst can list processes, query registry, access event logs. | None |
| 2026-04-14T03:22:04Z | Incident Response (Massimo) | Isolation verification from multiple sources: (1) ping from clinical VLAN, (2) ping from jumpbox, (3) netflow scan for 185.220.101.47, (4) endpoint agent status check | (1) Timeout, (2) Success, (3) Zero packets, (4) CONTAINED status | (1) Ping times out as expected. (2) Ping responds 4 ms round-trip. (3) Netflow shows zero packets to 185.220.101.47 for >2.5 min (since 03:19:18Z). (4) WazuhEDR: agent CONTAINED, last check-in 03:22:03Z. | None |
| 2026-04-14T03:25:30Z | Incident Response (Massimo) | Process snapshot and memory capture initiated from jumpbox for forensic preservation (second capture to confirm no changes post-isolation) | Memory and process snapshots captured; forensic imaging queued | Confirmed: wsl-export-memory.sh executed; memory capture to /evidence/IR-20260414-01/memory/wst-ws-031-post-isolation.mem (1.2 GB captured to date, still in progress). Process list exported; running processes include update.exe, powershell.exe, msbuild.exe confirmed still in memory (no cleanup detected). | None |

## Summary of Execution

✓ **Network Isolation**: WST-WS-031 moved to quarantine VLAN 999 at 03:19:04Z; clinically unreachable as of 03:19:04Z; jumpbox-only access confirmed.

✓ **C2 Severance**: Firewall rule blocking 185.220.101.47 deployed at 03:19:18Z; outbound C2 beacon severed (last packet 03:19:11Z); zero subsequent packets to attacker IP.

✓ **Endpoint Containment**: WazuhEDR containment flag set at 03:20:02Z; agent policy enforced (QUARANTINE_ISOLATION); no process execution or egress permitted except IR-authorized channels.

✓ **Forensic Access**: Jumpbox SSH access confirmed at 03:21:30Z; analyst tooling available; memory and process capture initiated for post-isolation state verification.

✓ **Verification**: Multi-source isolation confirmation at 03:22:04Z—clinical network unreachable, jumpbox accessible, netflow to C2 address at zero, endpoint agent reporting CONTAINED status.

**Total Execution Time**: 6 min 26 sec (03:19:04Z – 03:25:30Z)

**No deviations from plan.**

## Post-Execution Observations

- **MSBuild Process**: Still running (PID 8104) as of 03:21:30Z; malware unaware of network isolation (no error handling observed). Process will timeout on next C2 beacon attempt (~60–120 sec intervals typical for Tor beacons).

- **Persistence Mechanisms**: Registry RunKey (HKCU\Software\Microsoft\Windows\CurrentVersion\Run = update.exe) and scheduled task still active; will attempt re-execution on next user logon. Flagged for cleanup in remediation phase.

- **Clinical Impact**: dmarsh reassigned to spare workstation (WST-WS-044) at 03:15Z (prior to containment). Laboratory processing continues without delay. No patient care impact confirmed.

- **Firewall Rule**: Rule deployed on core firewall (Palo Alto PA-5220); mirrored to secondary firewall at 03:20:15Z for redundancy.

## Next Steps

1. **Forensic Imaging**: Complete post-isolation memory capture and initiate full disk imaging of WST-WS-031 (queued, ~8–10 hours for 500 GB).
2. **Malware Analysis**: Offline analysis of update.zip, update.exe, update.xml; escalate to threat intel team for attribution.
3. **Credential Rotation**: Force password reset for dmarsh; revoke session tokens from Azure AD and Office 365 (ongoing under PB-CRED-001).
4. **Registry Cleanup**: Remove persistence mechanisms (RunKey, scheduled task) during remediation phase (post-imaging, ~24h).
5. **Host Remediation**: Wipe and reimage WST-WS-031 once forensic imaging complete (~72h from now).

## Signatures

**Executed by**: Incident Response Team (Massimo, Maria Gonzalez, Taj Patel)  
**Verified by**: James Chen, IR Commander  
**Timestamp**: 2026-04-14T03:25:30Z  
**Status**: COMPLETE — No deviations from approved containment plan.
