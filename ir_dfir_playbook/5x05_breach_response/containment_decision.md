# Containment Decision: IR-2026-0420-01

| Strategy | Action | Threat Effect | Clinical Impact | Evidence | Time | Reversible | Risk |
|----------|--------|---------------|-----------------|----------|------|-----------|------|
| **A: Full Isolation** | All 5 hosts→VLAN 999 | C2 severed; no spread | 4 WS + file server offline; ED manual fallback | All preserved (memory, disk, logs) | 5–10 min | Yes | None |
| **B: Segmentation ← CHOSEN** | WS→VLAN 999; FILE-SVR egress filter | C2 severed WS; FW blocks FILE-SVR C2; lateral movement blocked | 4 WS offline; file server operational; PHI access preserved | All preserved | 10–15 min | Yes | File server on-network; mitigated by egress filter + account revocation + monitoring |
| **C: Endpoint Monitoring** | Wazuh quarantine; allow C2 beacon | Monitor attacker behavior; intelligence gathering | Minimal; hosts stay on network | Memory preserved; disk at risk | 2–3 min | Yes | **HIGH:** Ransomware execution destroys disk evidence & patient data |

## Chosen: Strategy B — Network Segmentation

**Authorization:** IR Commander + Clinical Lead  
**Rationale:** Balances forensic integrity vs. clinical continuity. Workstations isolated (4 beacons severed, no spread to file server). File server remains on-network but egress-filtered (C2 blocked) + jdoe disabled (credential path closed). Large exfiltration (2.4 MB from FILE-SVR-01 @ 2026-04-19T02:14:22Z) mitigated by filtering. Ransomware staging scripts present but not executed; network isolation eliminates C2 trigger channel. Evidence preserved (memory+disk captures occur before isolation). Clinical downtime bounded to 4 workstations; file server maintains PHI access for ED operations. Strategy A safer but clinically unacceptable (full ED downtime). Strategy C risky (ransomware execution during observation window).

**Rollback Trigger:** If file server egress filtering breaks legitimate workflows (Epic backup, licensing) within 1 hour → revert + escalate to downtime decision. Workstation isolation remains.

**Key Assumptions:** 4 WS loss absorbed by ED; FILE-SVR-01 criticality mandates partial isolation; 45.152.66.114 not legitimate vendor; jdoe only credential compromised (validate via auth logs); ransomware not executed at 19:52Z (beacon jitter suggests hours, not minutes, before execution command).
