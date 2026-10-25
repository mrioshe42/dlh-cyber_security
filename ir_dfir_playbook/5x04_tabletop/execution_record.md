# Execution Record

**Simulation date:** 2026-10-25 | **Simulated by:** Massimo

## INJ-00 (T+0)

**Responses:** James (SEV2, pull EDR 72hr, capture traffic). Sarah (Is it Nexus?). Dr. Morales (Evidence first). Robert (Check for agents at West/North).

**Evaluation:** Incident declared  | Right people notified  | Evidence before containment  | **Vendor as threat vector ** (Sarah mentions Nexus but team assumes malware on host, not supply-chain).

**Probe:** "What software creates the outbound connections?"  
**Reveal:** Team suspects local malware, not vendor build-pipeline compromise.

## INJ-01 (T+20)

**Responses:** James (Nexus agent is malware). Sarah (Isolation = RTO burn, continuity = unknown agent). Dr. Morales (Clinical impact?). Sarah (Surgery schedules packed). Helena (Called Nexus?). Lisa (Never tested 24x7 line).

**Evaluation:** Isolation vs. continuity tension recognized  | Tradeoffs articulated  | **Explicit decision deferred ** | **Clinical not consulted ** | **Nexus not called **

**Probe:** "Dr. Morales, isolation or continuity? Who decides?"  
**Reveal:** CISO defers, asks for more info. **DESIGN ISSUE #1: Isolation decision before integrity risk understood.**

## INJ-02 (T+45)

**Responses:** Robert (Agent can modify appointments). James (How verify?). Sarah (Epic audit exists but no detailed ehr-ingest logs). Lisa (Request Nexus logs, compare). Dr. Morales (Can't verify = assume compromise, patient safety + notification issue).

**Evaluation:** Data-integrity risk recognized  | **Nexus not asked for logs ** | **Epic audit not pulled ** | **CMO not consulted **

**Probe:** "Do you call Nexus now or decide isolation first?"  
**Reveal:** Team realizes INJ-01 decision should have included integrity risk context. Sequencing backwards.

## INJ-03 (T+75)

**Responses:** Helena (Clock starts T+0, not Nexus. 60 days to individuals. >500 in OR/WA = HHS + media). Dr. Morales (Are we over 500?). Lisa (Yes). Helena (Notification required, will draft statement).

**Evaluation:** Four-factor test  | Clock = T+0  | 60-day deadline  | 500-person threshold  | **Holding statement committed but not drafted ** | **Board not notified **

**Probe:** "Notify in 60 days but don't know if records were modified. How explain?"  
**Reveal:** Team uncomfortable with "reasonable likelihood" threshold. Wants forensic certainty. **ISSUE #2: HIPAA bar not clear.**

## INJ-04 (T+120)

**Responses:** Sarah (Decide?). James (Isolate, 4 hrs rebuild). Sarah (Clinics angry, manual fallback for surgeries). Dr. Morales (Wait—72-hr suspect data already in Epic. Should we know about tampering first?). Robert (Pull 3 flagged appointments, compare to Nexus logs).

**Evaluation:** Isolation scenario (ETA + fallback) ~Pass | Continuity scenario (investigate first)  | **Clinical input not formally documented ** | Decision revisited 

**Probe:** "Hour 3 of rebuild, not done. What happens to RTO?"  
**Reveal:** Sequencing issue critical. **ISSUE #1 reinforced.**

## INJ-05 (T+150)

**Responses:** Helena (No. Notify on MedDefense assessment, not Nexus confirmation. Threshold = reasonable likelihood. We have it: writes from compromised agent). Dr. Morales (Nexus protects their reputation; not our problem). Marcus (Public will think Nexus breached). Helena (Different framing: vendor compromise may have affected records).

**Evaluation:** Independent decision  | Nexus claim overridden  | Notification per 60-day deadline  | **Decision rationale unclear if documented ** | Informs Nexus (no approval) 

**Probe:** "Does Nexus's customer concern change timeline?"  
**Reveal:** No gap. Team stands firm.

## INJ-06 (T+180)

**Responses:** Marcus (Need statement 90 min). Helena (Acknowledge vendor, patient safety, notify per law, no specifics pending forensics). Dr. Morales (The 31 appointments?). Robert (Flag as pending verification, contact patients). Dr. Morales (Gap: zero visibility into whether Nexus evicted attacker from their infrastructure. Unanswered question).

**Evaluation:** Media escalated immediately  | Statement framework  | Content correct  | Nexus informed (no approval)  | Unresolved questions documented  | Control gap noted 

**Probe:** "If Nexus still compromised and you re-enable SCHED-SVR-01, what's your defense?"  
**Reveal:** Unanswered question has downstream impact. Missing: SLA on Nexus forensics completion.

## Design Feedback

### DF-01: Isolation Decision Sequencing (High Priority)  FIXED

**Problem:** INJ-01 forces isolation decision before INJ-02 reveals agent writes to Epic.  
**Fix applied:** INJ-01 inject text now includes "Preliminary analysis shows write access to ehr-ingest endpoint." Team now gets integrity risk context at decision point.

### DF-02: HIPAA Threshold Clarity (High Priority)  FIXED

**Problem:** Team uncomfortable with "reasonable likelihood of harm"—wants forensic certainty.  
**Fix applied:** INJ-03 pass criteria now explicitly states: "Threshold is likelihood (compromised agent + ePHI access), not forensic certainty. Notification required regardless of modification proof."

### DF-03: Clinical Leadership Missing (High Priority)  FIXED

**Problem:** Evaluation expects clinical sign-off but no clinical director in room.  
**Fix applied:** Added Dr. Ronald Wei (CMO) to Participants. INJ-01 now requires clinical phone consultation within 15 min.

### DF-04: Re-enablement Criteria (Minor)  FIXED

**Problem:** INJ-06 identifies "attacker still in Nexus?" without linking to safe re-enable decision.  
**Fix applied:** INJ-06 pass criteria now require team to name evidence Nexus must provide before SCHED-SVR-01 re-enablement.

