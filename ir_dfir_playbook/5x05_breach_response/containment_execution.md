# Containment Execution: IR-2026-0420-01

**Authorization:** Strategy B — IR Commander + Clinical Lead

## Execution Steps

| Phase | Step | Time | Host | Action | Result | Verified |
|-------|------|------|------|--------|--------|----------|
| **Isolation** | 1.1 | 20:35Z | CS-WS-101 | VLAN 118→999 (10.42.999.101) | DHCP 20:35:12Z; Wazuh checkin 20:35:18Z | ✓ Isolated |
| | 1.2 | 20:38Z | CS-WS-104 | VLAN 118→999 (10.42.999.104) | DHCP 20:38:09Z; Wazuh checkin 20:38:16Z | ✓ Isolated |
| | 1.3 | 20:40Z | CS-WS-107 | VLAN 118→999 (10.42.999.107) | DHCP 20:40:08Z; Wazuh checkin 20:40:15Z | ✓ Isolated |
| | 1.4 | 20:42Z | CS-WS-112 | VLAN 118→999 (10.42.999.112) | DHCP 20:42:07Z; Wazuh checkin 20:42:14Z | ✓ Isolated |
| **Segmentation** | 2.1 | 20:45Z | FILE-SVR-01 | FW egress filter: deny 45.152.66.114:443 | Rule deployed 20:45:18Z; mirror 20:45:52Z; beacon dropped 20:45:33Z | ✓ Blocked |
| | 2.2 | 20:48Z | FILE-SVR-01 | SMB ACL: revoke jdoe | ACL 20:48:15Z; jdoe sessions=0 @ 20:48:30Z; clinical users connected | ✓ Revoked |
| **Credential** | 3.1 | 20:50Z | AD | Disable jdoe; invalidate Kerberos tickets | Disabled 20:50:08Z; tickets invalidated 20:50:12Z; zero active sessions | ✓ Confirmed |
| | 3.2 | 20:52Z | Cloud | Revoke Azure AD tokens; terminate RDP | Revoked 20:52:14Z; RDP terminated 20:52:18Z; zero active sessions | ✓ Confirmed |
| **Perimeter** | 4.1 | 20:55Z | FW | Deny outbound to 45.152.66.114 | Primary 20:55:07Z; secondary 20:55:34Z; IP blocklisted 72h | ✓ Active |


## C2 Severance Verification (21:00Z)

**Netflow Query:** 0 packets to 45.152.66.114:443 from all hosts post-20:35Z. Last observed beacon: FILE-SVR-01 @ 2026-04-19T02:41:09Z.

**Firewall Logs:** Last denied packet FILE-SVR-01 @ 20:45:33Z (in-flight, dropped). Zero subsequent attempts. Beacon jitter (60±10s) shows no resumption.

**Wazuh Agent:** All isolated hosts CONTAINED+ISOLATED. Outbound: WazuthEDR server (10.42.1.100) + jumpbox only. No unexpected connections.

**Status:  C2 Beacon Severed**


## Timeline

```
20:35–20:42Z — Workstation VLAN isolation
20:45Z — File server egress filter
20:48Z — File server SMB ACL revocation
20:50–20:52Z — Credential revocation (AD + cloud)
20:55Z — Perimeter FW rule
21:00Z — C2 severance verified
21:15Z — All containment complete
```

---

## Deviations

None. One in-flight beacon from FILE-SVR-01 dropped at 20:45:33Z (expected timing). All actions completed within windows.

## Incident Timeline Entries (Append)

```
2026-04-20T20:35:00Z | ACTION | Taj Patel, Network Operations | CS-WS-101 VLAN 118→999 (10.42.999.101); isolated from clinical network; jumpbox access verified | containment_execution.md | confirmed

2026-04-20T20:38:00Z | ACTION | Taj Patel, Network Operations | CS-WS-104 VLAN 118→999 (10.42.999.104); isolated | containment_execution.md | confirmed

2026-04-20T20:40:00Z | ACTION | Taj Patel, Network Operations | CS-WS-107 VLAN 118→999 (10.42.999.107); isolated | containment_execution.md | confirmed

2026-04-20T20:42:00Z | ACTION | Taj Patel, Network Operations | CS-WS-112 VLAN 118→999 (10.42.999.112); isolated | containment_execution.md | confirmed

2026-04-20T20:45:00Z | ACTION | Taj Patel, Network Operations | FILE-SVR-01 egress filter: deny 45.152.66.114:443; FW rule deployed primary 20:45:18Z, secondary 20:45:52Z; beacon attempt dropped 20:45:33Z | containment_execution.md | confirmed

2026-04-20T20:48:00Z | ACTION | James Chen, IR Commander + Clinical Lead | FILE-SVR-01 SMB access: MEDDEFENSE\jdoe revoked from PHI shares; jdoe sessions disconnected 20:48:30Z; clinical users retained | containment_execution.md | confirmed

2026-04-20T20:50:00Z | ACTION | Maria Gonzalez, Endpoint Security | jdoe AD account disabled 20:50:08Z; Kerberos tickets invalidated 20:50:12Z (post-2026-04-17T14:00Z); password reset held for recovery verification | containment_execution.md | confirmed

2026-04-20T20:52:00Z | ACTION | Maria Gonzalez, Endpoint Security | Azure AD refresh tokens revoked 20:52:14Z; RDP sessions terminated 20:52:18Z; zero active sessions for jdoe | containment_execution.md | confirmed

2026-04-20T20:55:00Z | ACTION | Taj Patel, Network Operations | Perimeter firewall egress rule deployed: deny all outbound to 45.152.66.114; secondary firewall synced 20:55:34Z; IP added to threat intelligence blocklist (72-hour hold) | containment_execution.md | confirmed

2026-04-20T21:00:00Z | OBSERVATION | Scribe | Netflow verification: 0 packets to 45.152.66.114 from all compromised hosts post-isolation (window 20:35–21:00Z). Last pre-isolation beacon FILE-SVR-01 2026-04-19T02:41:09Z. Beacon jitter pattern analysis shows no C2 resumption. C2 beacon severed and verified | netflow export + firewall logs | confirmed

2026-04-20T21:05:00Z | OBSERVATION | Maria Gonzalez, Endpoint Security | Wazuh EDR verification: all four isolated workstations report CONTAINED+ISOLATED status; netstat shows zero outbound except WazuhEDR server (10.42.1.100) and jumpbox; QUARANTINE_ISOLATION policy active. Endpoint-level isolation verified | Wazuh agent + netstat | confirmed

2026-04-20T21:15:00Z | DECISION | James Chen, IR Commander | Containment phase complete. Status: (1) Four workstations isolated VLAN 999; (2) File server egress filtered (C2 blocked); (3) jdoe disabled AD+cloud; (4) Perimeter FW rule active; (5) C2 severed (verified netflow + endpoint); (6) Credential path closed. Severity SEV2 (ransomware not executed, limited exfiltration FILE-SVR-01 only). Rollback decision pending clinical impact assessment at 22:00Z. Next: forensic analysis + eradication planning | containment_execution.md | confirmed
```
