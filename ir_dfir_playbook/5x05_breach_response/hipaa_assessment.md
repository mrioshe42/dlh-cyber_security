# HIPAA Breach Risk Assessment: IR-2026-0420-01

**Assessment Date:** 2026-04-20 | **Conducted By:** Massimo (on-call IR) | **Reviewed By:** Helena Reyes, General Counsel  
**PHI Scope:** 1,847 patient clinical files (lab results, ER notes, progress notes) accessed 2026-04-19T02:14–41Z

## Factor 1: Nature & Extent of PHI
**Evidence:** FILE-SVR-002 shows 1,847 read events (Event ID 4663) on \\clinical\\labs\ and \\clinical\\notes\ — lab panels, ER admission notes, clinical progress notes with patient identifiers.  
**Conclusion:** HIGH RISK — Sensitive clinical PHI with full identifiers (MRN, dates, diagnoses, lab values).  
**Confidence:** Confirmed

## Factor 2: Who Accessed & How
**Evidence:** FILE-SVR-001: jdoe logon via Kerberos @ 02:14:00Z from CS-WS-101. MEM-004: svchost32.exe dumped lsass.exe credentials. jdoe is scheduler with no legitimate clinical access.  
**Conclusion:** CONFIRMED UNAUTHORIZED — Attacker used stolen credentials (Pass-the-Ticket) via beacon process.  
**Confidence:** Confirmed

## Factor 3: PHI Actually Acquired?
**Evidence:** PROXY-003: 2.4 MB exfiltrated to 45.152.66.114:443 @ 02:14:22Z (21 sec after logon). Concurrent file reads + C2 beacon through 02:41Z.  
**Conclusion:** PROBABLE ACQUISITION — Files read and transmitted to attacker IP in readable form.  
**Confidence:** Probable

## Factor 4: Mitigation Efforts
**Evidence:** Isolation @ 20:35Z (17+ hrs AFTER access ended 02:41Z). Credential revocation @ 20:50Z. No real-time detection during breach window.  
**Conclusion:** MINIMAL — All actions post-exfiltration. No prevention during 27-minute window.  
**Confidence:** Confirmed

## Determination

| Factor | Result |
|--------|--------|
| Nature/Extent | **FAILS** (sensitive PHI) |
| Unauthorized Access | **FAILS** (confirmed) |
| Actual Acquisition | **FAILS** (probable) |
| Mitigation | **FAILS** (post-incident) |

**→ NOTIFICATION REQUIRED** — Low-probability-of-compromise threshold NOT met.

**Authority:** Helena Reyes, General Counsel (signature target: 2026-04-21T06:00Z)

**Action:** Notify affected individuals (~180–300 patients), HHS, media (if >500), per HIPAA Breach Notification Rule.
