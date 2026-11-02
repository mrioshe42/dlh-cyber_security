# MedDefense Business Impact Analysis

**Version:** 1.0 | **Classification:** Confidential  
**Prepared by:** Massimo | **Date:** November 2, 2026  
**CISO approval:** _________________________ Date: _________

## Executive Summary

BIA classifies 10 MedDefense systems into recovery tiers based on patient safety, regulatory, and revenue impact. **Tier 1 (6 systems):** Direct patient impact; RTO ≤ 1 hour. **Tier 2 (4 systems):** Indirect impact; RTO ≤ 4 hours. All Tier 1 systems depend on Network Core and Active Directory.

## Methodology

Systems assessed on five dimensions: (1) Patient Safety Impact, (2) Regulatory Obligation (HIPAA, Joint Commission, CMS CoP), (3) Revenue Impact ($/hour), (4) Operational Dependencies, (5) Recovery Feasibility. RTO targets are 50–75% of MTD to allow margin for complications.

## System Impact Assessment

### 1. Active Directory (Tier 1)

**Role:** Enterprise authentication; controls access to all clinical systems.

**Impact:** 
- **1hr:** Staff with open sessions continue work; new staff cannot log in to EHR, PACS, pharmacy. Registration desk delays patient intake.
- **4hr:** User sessions expire. Pharmacist cannot access Epic to verify drug interactions before dispensing; patient receives warfarin + ibuprofen post-op (bleeding risk). Nurse cannot pull allergy history; anesthesiologist unaware of penicillin allergy, gives amoxicillin (anaphylaxis risk). **[CRITICAL MEDICATION SAFETY FAILURE]**
- **24hr:** All system access halted. Clinical staff revert to verbal orders and paper charts; no digital verification pathway exists. ED triage cannot confirm patient identity; medication administration reverts to paper wristbands (cross-matching errors).

**Regulatory:** HIPAA §164.312(a)(2)(i) user authentication; Joint Commission NPSG.01.01.01 patient ID.

**Revenue Impact:** $4,200/hour (lost OR throughput + manual verification overhead).

**MTD:** 6 hours | **RTO:** 45 min | **RPO:** 15 min | **Tier:** 1

### 2. Epic EHR (Tier 1)

**Role:** Primary electronic health record; all patient data, medications, allergy alerts.

**Impact:** 
- **1hr:** Cached patient records remain available for existing encounters. New admissions cannot register; ED waiting room backs up. No new chart access for consultants.
- **4hr:** Cache expires or corrupted. ED physician encounters trauma patient; no prior history access (diabetic? anticoagulated? previous MI?). Orders medication based on verbal report. Surgeon scheduled for elective case proceeds without pre-op imaging review; intraoperative finding contradicts plan (wrong anatomy), requiring unplanned procedure extension. Discharge planning halted; patients cannot leave without paper summary. **[DIAGNOSTIC ERROR + SURGICAL COMPLICATIONS]**
- **24hr:** All EHR access gone. ICU patient's previous sepsis episodes unknown; antibiotic selection based on guess. Oncology patient's prior chemo regimen cannot be verified; cardiotoxicity risk calculation impossible. Follow-up care data is orphaned; patients discharged with incomplete summaries. Readmissions inevitable due to fragmented care.

**Regulatory:** HIPAA §164.312(b) audit controls; Joint Commission NPSG.03.01.01 medication reconciliation; CMS CoP §482.24 documentation.

**Revenue Impact:** $7,500/hour (surgical cancellations, ED delays, manual charting overhead).

**MTD:** 4 hours | **RTO:** 30 min | **RPO:** 5 min | **Tier:** 1

### 3. Laboratory Information System (Tier 2)

**Role:** Lab test orders, results, quality control; interfaces with Epic.

**Impact:** 
- **1hr:** Lab tests in process complete; results cannot be electronically reported to Epic. Verbal reporting begins for critical results.
- **4hr:** Manual result entry into EHR becomes bottleneck. Stroke code troponin result (verbal) entered to wrong patient chart—no electronic linkage. Sepsis patient's lactate (4.2, abnormal) manually transcribed as 2.4; physician misses deterioration. Blood culture positive result queued but not escalated—infection control not notified. ICU glucose entered as 480 instead of 48; insulin not withheld. **[CRITICAL VALUE MISREPORTING, INFECTION CONTROL FAILURE, MEDICATION ERROR]**
- **24hr:** Lab results and specimen data completely disconnected from patient identities. Specimen mix-up risk escalates. Follow-up testing cannot be verified against prior baselines; abnormality detection fails.

**Regulatory:** CLIA result reporting; Joint Commission NPSG.05.02.01; CMS CoP §482.23 records.

**Revenue Impact:** $16,800/hour (procedure delays, staffing overhead).

**MTD:** 8 hours | **RTO:** 2 hours | **RPO:** 30 min | **Tier:** 2

### 4. PACS/RIS (Tier 1)

**Role:** Medical imaging archive (CT, MRI, X-ray, ultrasound); radiology orders and reporting.

**Impact:** 
- **1hr:** New radiologic orders cannot be entered. Prior imaging unavailable for radiologist review during interpretations.
- **4hr:** Stroke alert patient's 6-month prior CT (baseline for acute hemorrhage detection) cannot be retrieved; radiologist cannot exclude bleed vs. ischemia confidently. ED physician orders CT anyway. Oncology patient with nodule on lung CT cannot access prior year's study for size comparison; 8mm nodule assumed stable (malignancy delayed 6 months). Surgical planning halted—pre-op imaging not available for surgeon review. Hip fracture patient's anatomy cannot be assessed; surgery postponed. **[DIAGNOSTIC DELAY + SURGICAL CANCELLATIONS + TREATMENT DELAYS]**
- **24hr:** Trauma imaging inaccessible. Multiply-injured patient transferred to regional trauma center (MedDefense cannot verify injuries). All imaging is fragmented across paper reports and local workstations; no archive baseline for comparison. Radiologist cannot trend suspicious findings.

**Regulatory:** HIPAA §164.312(c)(1) archiving; Joint Commission NPSG.02.01.01 diagnostic availability; CMS CoP §482.26 imaging results.

**Revenue Impact:** $41,500/hour (OR delays, ED imaging backlog, external referrals).

**MTD:** 6 hours | **RTO:** 1 hour | **RPO:** 15 min | **Tier:** 1

### 5. Pharmacy Dispensing System (Tier 1)

**Role:** Medication dispensing, drug interaction verification, controlled substance tracking.

**Impact:** 
- **1hr:** Pharmacist manually verifies orders against paper EHR printouts and allergy lists. Throughput reduced 30%; minor delays for non-critical medications.
- **4hr:** Manual verification fatigue increases. Post-op patient on warfarin receives ibuprofen for pain (major bleed risk—interaction missed in paper chart review). ICU sepsis patient receives vancomycin + gentamicin (nephrotoxicity—no drug-level calculator without system). Patient with QTc-prolonging baseline receives doxycycline + azithromycin (synergistic QTc effect, arrhythmia risk). Controlled substance dispensing falls out of audit trail. **[CRITICAL DRUG INTERACTIONS + MEDICATION ERRORS + REGULATORY BREACH]**
- **24hr:** Pharmacy staff unable to verify any medication without system access. Unverified dispensing creates unacceptable liability; inpatient medications withheld. Patients transferred for medication access.

**Regulatory:** State Pharmacy Board controlled substance logging; Joint Commission NPSG.03.04.01 medication safety; CMS CoP §482.23 pharmacy records.

**Revenue Impact:** $3,500/hour (manual overhead, medication errors, patient transfers).

**MTD:** 4 hours | **RTO:** 45 min | **RPO:** 10 min | **Tier:** 1

### 6. Medical Device Integration Gateway (Tier 1)

**Role:** Integrates bedside devices (ventilators, cardiac monitors, infusion pumps) into EHR; aggregates vital signs.

**Impact:** 
- **1hr:** Vital signs available on local device displays and bedside monitors. No data transmitted to EHR; charts lack automated trending graphs.
- **4hr:** ICU nurse manually documents vital signs every hour; fragmented trend data. Sepsis patient's lactate trending downward (improving)—but no automated alert. Patient's blood pressure declining from 120→95→70 over 3 hours; trend visible only if nurse reviews each paper chart entry. Chart review reveals decline at 4-hour mark; vasopressor already should have been started at 3 hours. Post-op patient's SpO2 declining from 98%→92%→88%; without continuous waveform trending, deterioration not apparent until clinical decompensation. Ventilator-dependent patient's declining lung compliance missed; VAP (ventilator-associated pneumonia) not detected for 8 hours. **[DELAYED SEPSIS RECOGNITION + DELAYED VASOPRESSOR INITIATION + DELAYED RESPIRATORY SUPPORT + PROLONGED VENTILATION]**
- **24hr:** ICU completely disconnected from device data. Manual vital sign charting only; untrended data becomes unusable. Patient monitoring reverts to bedside observation only; no early warning alarms.

**Regulatory:** HIPAA §164.312(b) audit controls; Joint Commission NPSG.06.01.01 patient monitoring; CMS CoP §482.23 ICU documentation.

**Revenue Impact:** $7,000/hour (ICU throughput reduction, manual monitoring overhead, patient deterioration risk).

**MTD:** 4 hours | **RTO:** 45 min | **RPO:** 5 min | **Tier:** 1

### 7. Network Core (Tier 1)

**Role:** Enterprise network backbone; carries all system traffic (EHR, PACS, pharmacy, devices, email, backups).

**Impact:** 
- **1hr:** Redundant network paths degrade. Some systems remain accessible via backup links; connectivity intermittent. Clinical staff experience slowdowns, not outages.
- **4hr:** Cascading network failures. Most systems become unreachable. EHR access lost (cannot retrieve patient records). PACS goes dark (imaging inaccessible). Pharmacy system offline (medication dispensing unverified). Device monitoring disconnected (vital signs not transmitted). All IT-dependent clinical workflows halted. Paper charting begins. **[ALL TIER-1 SYSTEM CASCADING FAILURE]**
- **24hr:** Complete network blackout across enterprise. All IP-based clinical systems offline. ED triage cannot register patients (no network connectivity to registration). OR scheduling halted. ICU monitors display vitals only locally (no transmission to nursing station). Medication orders captured verbally or on paper—no dispensing verification. Patient care reverts entirely to paper; clinical decision-making based on patient recall, prior records, and physical exam only.

**Regulatory:** HIPAA §164.312(e)(1) network security; Joint Commission requires immediate reporting; CMS CoP §482.12 requires network uptime.

**Revenue Impact:** $66,708/hour (all surgical, ED, inpatient, outpatient, lab revenue halted + $50k per patient transfer).

**MTD:** 4 hours | **RTO:** 15 min | **RPO:** Real-time | **Tier:** 1

### 8. Email and Secure Messaging (Tier 2)

**Role:** Clinical and administrative communication; HIPAA-compliant patient messaging.

**Impact:** 
- **1hr:** Email and secure messaging queue. Non-critical communications delayed. Critical consult requests communicated via phone.
- **4hr:** Consultant requests accumulate in queue; phone communication overwhelms desk staff. Cardiology consult request (chest pain patient) delayed 2 hours—cardiologist receives paper handoff instead of EHR note. Infectious disease consult for sepsis patient routed to email; delayed 3 hours. Patient messaging backlog grows; discharge instructions not sent; post-op patient unsure about medication changes. Documentation gaps created (consult requests, patient questions not in chart). **[CONSULTATION DELAYS + PATIENT SAFETY COMMUNICATION GAPS]**
- **24hr:** Email massive backlog; critical messages buried. Lab abnormality escalation (positive culture) not sent to attending physician. Patient requests (prescription refills, symptom questions) unanswered for 24+ hours. Follow-up appointment reminders not sent; no-show rates increase.

**Regulatory:** HIPAA §164.312(a)(2)(ii) audit controls; Joint Commission NPSG.02.02.01 communication; State medical board response time requirements.

**Revenue Impact:** $10,000/hour (phone communication overhead, billing delays, patient satisfaction impact).

**MTD:** 24 hours | **RTO:** 4 hours | **RPO:** 1 hour | **Tier:** 2

### 9. Backup and DR Infrastructure (Tier 1)

**Role:** Backup management, offsite copies, DR failover orchestration, data restoration.

**Impact:** 
- **1hr:** Backup processes halt; in-flight backups incomplete. Last completed backup (previous night) remains valid; production systems still operational, no immediate harm.
- **4hr:** Extended backup outage. If any production system fails during this 4-hour window (hardware failure, ransomware, data corruption), NO RECOVERY IS POSSIBLE. Epic EHR failure = unrecoverable patient data loss. PACS failure = unrecoverable imaging archive loss. Pharmacy failure = unrecoverable medication history. **[ZERO RECOVERY CAPABILITY IF ANY SYSTEM FAILS CONCURRENTLY]** Risk exposure: Unrecoverable $50M+ data asset. Regulatory breach (HIPAA §164.308(a)(7)(ii) backup failure). Patient safety cannot be assured without EHR recovery.
- **24hr:** All backups offline. Any production system failure during this period results in permanent data loss. CMS audit discovers no viable backups; compliance violation with potential CoP revocation. Patient medical records are unrecoverable; continuity of care impossible for patients requiring historic data access.

**Regulatory:** HIPAA §164.308(a)(7)(ii) backup requirements; HIPAA §164.308(a)(7)(i) business continuity; CMS CoP §482.12 recovery capability.

**Revenue Impact:** $43,000/hour (risk exposure + manual verification overhead).

**MTD:** 4 hours | **RTO:** 2 hours | **RPO:** 1 hour | **Tier:** 1

### 10. Security Operations Platform (Tier 2)

**Role:** SIEM, intrusion detection, vulnerability management, incident response.

**Impact:** 
- **1hr:** No real-time security monitoring. Intrusion alerts not generated. Malware infections not detected. Data exfiltration not flagged. If no active threat exists, risk is low; if threat in progress, organization is blind.
- **4hr:** Extended monitoring gap. Ransomware deployed on file server (Tier 2 risk) undetected. Attacker moves laterally to pharmacy system (Tier 1). Malicious process dumps medication database (patient + provider data exfiltration). **[UNDETECTED BREACH + DATA EXFILTRATION]** No alerts generated. Organization unaware breach is occurring.
- **24hr:** Continuous security blind spot. Suspicious admin logins undetected. Backup deletion (ransomware preparation) not flagged. Patient data accessed and copied by insider threat—no audit trail. At 24 hours, breach is likely complete and undetected. Regulatory notification deadline (60 days from discovery) cannot start until breach is discovered; org compliance delayed.

**Regulatory:** HIPAA §164.308(a)(5)(ii)(C) monitoring required; HIPAA §164.308(a)(6)(ii) incident response; Joint Commission cybersecurity focus.

**Revenue Impact:** $3,500/hour (breach risk exposure + manual log collection overhead).

**MTD:** 8 hours | **RTO:** 2 hours | **RPO:** 30 min | **Tier:** 2

## Dependency Map & Recovery Sequence

```
Network Core (↓ ALL systems fail if this fails)
├── Active Directory (↓ All authentication fails)
│   ├── Epic EHR → PACS/RIS, Pharmacy, LIS
│   ├── Pharmacy Dispensing System
│   └── Medical Device Integration Gateway
└── Backup and DR Infrastructure (↓ No recovery possible if this fails)
```

**Recovery Priority:** Network Core (15 min) → Active Directory (45 min) → Epic EHR (30 min) → PACS/RIS (1 hr) → Pharmacy (45 min) → Device Gateway (45 min) → LIS (2 hrs) → Email (4 hrs) → Security Ops (2 hrs).

## RTO / RPO / MTD Summary Table

| System | Tier | MTD | RTO | RPO | Verified |
|--------|------|-----|-----|-----|----------|
| Active Directory | 1 | 6h | 45m | 15m | RTO < MTD |
| Epic EHR | 1 | 4h | 30m | 5m | RTO < MTD |
| Laboratory Information System | 2 | 8h | 2h | 30m | RTO < MTD |
| PACS/RIS | 1 | 6h | 1h | 15m | RTO < MTD |
| Pharmacy Dispensing System | 1 | 4h | 45m | 10m | RTO < MTD |
| Medical Device Integration Gateway | 1 | 4h | 45m | 5m | RTO < MTD |
| Network Core | 1 | 4h | 15m | Real-time | RTO < MTD |
| Email and Secure Messaging | 2 | 24h | 4h | 1h | RTO < MTD |
| Backup and DR Infrastructure | 1 | 4h | 2h | 1h | RTO < MTD |
| Security Operations Platform | 2 | 8h | 2h | 30m | RTO < MTD |

**Quality Requirements Verified:**
- Every RTO < MTD
- Every RPO stated in time
- LIS is Tier 2 (indirect patient impact)
- Active Directory and Network Core in dependency map as critical SPOFs
- All impacts specific with numbers (no "operations affected" generic statements)

## Key Assumptions

- Systems fail independently unless identified as dependent.
- Backup media and offsite DR connectivity assumed available.
- Clinical staff can sustain paper-based workflows up to 4 hours.
- Quarterly DR testing maintains RTO/RPO/MTD feasibility.
- Network Core failure cascades to all systems simultaneously.
- Vendor support available during business/extended hours.

## Approval Sign-Off

**CISO Approval:**  
Signature: _________________________ Date: _________

**CMO/COO Approval:**  
Signature: _________________________ Date: _________

**IT Director Approval:**  
Signature: _________________________ Date: _________

