# Containment Decision: IR-20260414-01

**Incident**: Compromised clinical workstation (WST-WS-031); malware execution and C2 beaconing to Tor exit relay  
**Evidence Preservation**: Complete (memory, processes, network, telemetry, logs, malware files hashed and verified)  
**Time Window**: Evidence preservation ends 2026-04-14T03:14:18Z; containment decision required by 03:20Z

## Candidate Strategies

### A. Network Isolation (Quarantine VLAN)

**Action**: Move WST-WS-031 to network quarantine VLAN 999; block all outbound traffic except to IR jumpbox (10.42.1.50:22); allow return inbound only from jumpbox.

**Attacker Effect**: 
- C2 beacon to 185.220.101.47:443 severed immediately
- On-host observation paused (no exfiltration possible)
- Attacker unaware of containment; future beacons fail to respond

**Evidence Effect**: 
- Volatile memory preserved on-host for 24–72h
- Running processes remain for inspection
- Persistence mechanisms (registry, scheduled tasks) remain intact on disk
- Network capture possible for any beacon attempts

**Patient Care Effect**: 
- WST-WS-031 unavailable for laboratory operations (~4h expected)
- West Campus Lab has 4 spare workstations available; no patient care impact
- dmarsh reassigned to spare workstation immediately

**Time to Execute**: ~5 min (network switch update + firewall rule push)

**Reversibility**: Fully reversible (restore VLAN membership within 5 min if unintended impact)

### B. Host Power-Off

**Action**: Remote power-off WST-WS-031; pull power supply; seal as evidence.

**Attacker Effect**: 
- C2 severed immediately
- Attacker on-host process killed
- No further observation or persistence execution possible

**Evidence Effect**: 
- Volatile memory DESTROYED (cannot be recovered after power loss)
- Process tree LOST (no snapshot available)
- Network connections LOST (closed on shutdown)
- Disk and registry preserved (can be recovered via forensic imaging)
- Persistence mechanisms remain on disk but cannot be analyzed in-memory

**Patient Care Effect**: 
- WST-WS-031 unavailable indefinitely (under forensic hold)
- dmarsh and lab operations impact unknown; may require extended downtime if spare workstations are insufficient
- Reputation risk if lab processing is delayed due to workstation seizure

**Time to Execute**: ~2 min

**Reversibility**: Not reversible; triggers forensic imaging chain of custody, extends IR timeline by days

### C. Selective Process Kill + Egress Block

**Action**: 
1. Kill MSBuild.exe (PID 8104) and PowerShell (PID 7812) 
2. Kill update.exe (PID 7204) and any child processes
3. Apply Windows Firewall egress rule to block TCP port 443 outbound for SYSTEM/user account
4. Preserve registry and scheduled tasks for later remediation

**Attacker Effect**: 
- C2 process killed; beacon fails
- Persistence mechanisms remain (registry, scheduled task) and may re-execute on next logon
- Attacker may have undetected child processes or lateral movement
- Risk of missed processes leading to continued infection

**Evidence Effect**: 
- Volatile memory preserved (attacker processes killed but memory state remains)
- Running process snapshot before kill is available
- Network connections still visible (kill does not erase connection history)
- Persistence on-disk remains intact for forensic analysis
- Risk: some malware may detect kill attempt and self-destruct artifacts

**Patient Care Effect**: 
- WST-WS-031 remains on network and available (after process termination)
- dmarsh can resume work immediately (after firewall rule deployment)
- Minimal downtime (~10 min)

**Time to Execute**: ~8 min (remote kill commands + firewall rule deployment)

**Reversibility**: Partially reversible (firewall rule can be removed; killed processes cannot be un-killed; may require reboot to clear persistence)

## Chosen Strategy: A (Network Isolation)

**Rationale**: Network isolation is the optimal choice because it severs the C2 beacon immediately and irreversibly while preserving all volatile evidence (memory, processes, network state) for forensic analysis. This strategy remains fully reversible if unintended clinical impact occurs, and the West Campus Lab has four spare workstations available, ensuring patient care is not disrupted. Option B destroys volatile memory—a non-recoverable loss critical to forensic investigation and malware analysis. Option C risks missed persistence mechanisms and does not definitively block the attacker from future observation; the firewall rule is also subject to host-side bypass. Option A provides the strongest evidence preservation posture with acceptable clinical impact.


## Execution Timeline

| Event | Timestamp | Duration |
|-------|-----------|----------|
| Evidence preservation complete | 2026-04-14T03:14:18Z | — |
| Containment decision made | 2026-04-14T03:17:42Z | — |
| VLAN move executed | 2026-04-14T03:19:04Z | ~5 min |
| dmarsh reassigned to spare WS | 2026-04-14T03:21:00Z | ~2 min |
| Jumpbox access granted (IR team) | 2026-04-14T03:22:15Z | ~1 min |

**Total decision-to-containment window**: ~8 minutes

## Approval Authority

**Approved by**: James Chen, SOC Lead / IR Commander  
**Approval timestamp**: 2026-04-14T03:17:00Z  
**Signature**: Authorized; no exceptions or overrides requested

## Rollback Plan

**Trigger**: Lab operations report unavailable spare workstations or critical test bottleneck within 30 minutes of isolation.

**Rollback procedure**:
1. IR Commander notified of impact
2. WST-WS-031 VLAN membership reverted to production VLAN (10.42.118.0/24) within **5 minutes**
3. Firewall jump-box access rule removed
4. Fall back to Strategy C: selective process kill + egress block (execute within 2 hours)
5. dmarsh notified of continued monitoring and process restrictions

**Rollback authorization**: IR Commander approval required (no delegated authority)

## Decision Record for Incident Timeline

Add the following DECISION entry to incident_timeline.md at 2026-04-14T03:17:42Z:

```
- 2026-04-14T03:17:42Z | DECISION | James Chen, IR Commander | Containment strategy selected: Network isolation (Strategy A). Rationale: preserves all volatile evidence, severs C2 immediately, remains reversible, and clinical impact is bounded by available spare workstations. Execution approved for 2026-04-14T03:19:04Z. | source=containment_decision.md | certainty=confirmed
```

## Next Steps (Task 4)

1. Execute network isolation (move WST-WS-031 to VLAN 999)
2. Verify C2 beacon failure (monitor proxy logs / network telemetry)
3. Confirm dmarsh reassigned to spare workstation
4. Begin malware analysis and forensic imaging of preserved evidence
5. Document remediation plan (registry cleanup, scheduled task removal, reimaging schedule)
