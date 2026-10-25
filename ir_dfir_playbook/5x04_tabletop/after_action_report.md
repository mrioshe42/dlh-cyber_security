# After-Action Report

**Exercise:** 2026-10-24 | **Report:** 2026-10-25 | **Facilitator:** massimo  
**Participants:** Dr. Patricia Morales (CISO), James Chen (IR Commander), Sarah Park (IT Director), Robert Kim (Infrastructure), Mike Torres (Network), Helena Reyes (GC), Marcus Webb (Communications), Lisa Tanaka (Vendor Risk), Dr. Ronald Wei (CMO)  
**Classification:** Internal

## Executive Summary

Supply-chain compromise via trusted vendor update (malware in code-signed Nexus agent). Four critical gaps: (1) vendor-as-vector not recognized as threat dimension; (2) isolation decision made before data-integrity risk understood (sequencing backwards); (3) HIPAA "reasonable likelihood of harm" threshold unclear, causing hesitation to notify; (4) BA 24x7 communication path untested. **Most critical action:** Joint tabletop with Nexus SecOps within 60 days—test 24x7 line, confirm <15 min response SLA, document escalation to CISO.

## Findings

| ID | Inject | Cap | Gap | Severity | Action | Owner | Days | Validation |
|----|--------|-----|-----|----------|--------|-------|------|-----------|
| F-001 | INJ-00 | CAP-01 | Vendor-as-vector not recognized | P1 | Add vendor context check to severity matrix before containment | James Chen (SOC) | 7 | Matrix updated |
| F-002 | INJ-01 | CAP-02 | BAA 24x7 untested, no confidence in response time | P1 | Joint Nexus tabletop: test contact, confirm <15 min SLA, document CISO escalation | Dr. Morales (CISO) | 60 | Joint exercise completed, SLA confirmed |
| F-003 | INJ-01 | CAP-03 | Isolation decision before integrity risk understood; sequencing backwards | P1 | Reorder playbook: integrity assessment before isolation decision. Add "writes to Epic?" check at alert stage | Sarah Park (IT) | 14 | Playbook reordered, INJ-01 updated |
| F-004 | INJ-02 | CAP-06 | Data-integrity verification missing; cannot detect appointment modification | P1 | Design Epic-vendor checklist: trigger on BA compromise, compare Nexus outbound vs. Epic inbound logs | Robert Kim (Infrastructure) | 21 | Checklist exists, reviewed by CMO/Epic admin |
| F-005 | INJ-03 | CAP-05 | HIPAA "reasonable likelihood" threshold unclear; team wants forensic certainty | P1 | Document threshold in playbook: reasonable likelihood = compromised agent + ePHI access (no verification required). Notification mandatory regardless of exfiltration proof. GC/CISO sign-off. | Helena Reyes (GC) | 7 | Playbook signed, training done |
| F-006 | INJ-01 | CAP-03 | Clinical not in IR room; decisions made without clinical sign-off | P2 | Add CMO to IR team from declaration. Require clinical phone consultation <15 min of isolation question | Dr. Ronald Wei (CMO) | 3 | CMO added to IR contacts |
| F-007 | INJ-04 | CAP-03 | Operational communication to clinics missing; no ETA or fallback | P2 | Create escalation template: isolation chosen → notify clinics <5 min (ETA + manual fallback procedure), IT updates every 30 min | Sarah Park (IT) | 7 | Template created, tested |
| F-008 | INJ-06 | CAP-07 | Re-enablement criteria undefined; cannot name what Nexus must prove safe to restore | P2 | Add to playbook: Nexus must provide (a) code-signing cert revocation attestation, (b) forensics completion, (c) attacker eviction confirmation | Marcus Webb (Communications) | 14 | Criteria in playbook, shared with Nexus CISO |
| F-009 | INJ-03,04 | CAP-08 | Executive briefing template missing; no 90-min structure | P2 | Create one-page template: what we know (facts), unknown (open questions), timeline (actions), impact (patients), HIPAA (clock), BC (RTO), milestones (4 hrs) | Dr. Morales (CISO) | 10 | Template exists, time-to-brief measured |
| F-010 | INJ-00 | CAP-01 | Update trustworthiness ambiguous; code-signing cert only, no hash pin (2025-11-14 residual) | P3 | Escalate to Nexus CISO: request client-side code hash validation mechanism (not signature alone) | Lisa Tanaka (Vendor Risk) | 90 | Vendor review 2026-11-14 |

## P1 Narratives

**F-001: Vendor-as-Vector Not Recognized**  
Team suspected local malware instead of recognizing Nexus agent or update channel. Vendor integration layer never named during alert classification. 20 minutes investigating "host compromise" before advisory arrived. Vendor-as-vector investigations require different strategies; naming the update channel early would have accelerated investigation 15+ min. Action: Add vendor context check (vendor on host? recent update? known vendor incident?) to severity_matrix.md Tier 2 before containment discussed. Owner: James Chen (SOC), 7 days.

**F-002: Business Associate Communication Path Untested**  
BAA requires Nexus notify within 24 hrs of Nexus discovery. 24x7 contact exists (soc@nexushealth.io, +1 512 555 0184) but never called. No confidence in response time. Team deferred vendor communication during isolation decision. Vendor coordination is time-sensitive; MedDefense cannot make isolation/notification decisions without knowing Nexus's incident status. 24-hour BAA notice requirement unenforceable if communication untested. Action: Joint tabletop within 60 days—test 24x7 line, confirm <15 min response, document CISO escalation path. Owner: Dr. Morales (CISO), 60 days.

**F-003: Isolation Decision Before Integrity Risk Understood (Sequencing)**  
INJ-01: team decided isolation without knowing Nexus agent writes to ehr-ingest. INJ-02: forensics revealed 72-hour write pattern. Team realized isolating before understanding record-integrity risk meant burning RTO to stop data flow that had already happened 72 hours. BC decisions require all material facts; understanding tampering risk is essential context. Action: Reorder IR playbook—integrity assessment before isolation decision. Add to INJ-01 inject text: "Preliminary analysis shows agent spawned write connections to ehr-ingest endpoint. Do not yet know if writes modified data." Owner: Sarah Park (IT), 14 days.

**F-004: Data Integrity Verification Process Missing**  
Compromised agent had write access to Epic ehr-ingest. No procedure to validate whether appointments were modified. MedDefense does not log detailed ehr-ingest payloads (only "connection succeeded"). Could not independently compare Nexus sends vs. Epic records. No process to interpret discrepancies (glitch vs. tampering). Patient safety depends on verification; silent cancellation due to tampering = no-show for surgery. Action: Design Epic-vendor data integrity checklist triggered on BA compromise—(1) identify systems writing to Epic, (2) request vendor outbound logs for compromise window, (3) pull Epic audit logs, (4) compare send vs. receive, (5) contact CMO + Epic admin for clinical interpretation, (6) flag discrepancies as pending verification. Owner: Robert Kim (Infrastructure), 21 days.

**F-005: HIPAA "Reasonable Likelihood of Harm" Threshold Unclear**  
Four-factor assessment performed correctly. Team hesitated at "probability of harm"—wanted forensic proof of modification before notifying. HIPAA threshold (45 CFR 164.404(b)(1)) is "reasonable likelihood" of harm, not certainty. Compromised agent with write access to 1,500+ ePHI records meets threshold. Delaying until forensics complete (7–10 days) risks missing 60-day notification window. Action: Document threshold explicitly in IR playbook—"Reasonable likelihood = compromised agent + ePHI access + no independent verification possible. Notification mandatory regardless of exfiltration/modification proof." GC and CISO sign-off. Owner: Helena Reyes (GC), 7 days.

## What Worked

1. **Rapid incident classification:** James Chen declared SEV2 <2 min. Severity process sound; gap was adding vendor context, not classification structure.
2. **Complete four-factor HIPAA assessment:** Helena Reyes + Dr. Morales systematically walked all four factors, correctly identified clock=T+0, checked state thresholds. Assessment structure solid.
3. **Independent vendor notification decision:** GC and CISO rejected Nexus pressure to delay; correctly determined MedDefense notification authority independent of vendor forensics. Decision authority appropriate.

## Sign-Off

**Facilitator:** massimo | **CISO:** Dr. Patricia Morales | **GC:** Helena Reyes | **Date:** 2026-10-25
