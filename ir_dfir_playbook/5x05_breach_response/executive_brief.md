# Executive Brief: Patient Data Breach
**IR-2026-0420-01 | 2026-04-21**

## Summary
Patient clinical records (1,847 files) were accessed and sent to an attacker April 18–19. We stopped the attacker on April 20. Patient care is unaffected. We are notifying affected patients per law.

## What Happened

**April 17:** Staff member opened phishing email with malware → downloaded to ED workstation (CS-WS-101).

**April 18–19:** Attacker stole login credentials, spread malware to 3 more workstations, accessed file server, read 1,847 patient files (lab results, ER notes, clinical notes), transmitted 2.4 MB to attacker.

**April 20:** We discovered incident at 19:43Z, isolated all systems by 20:35Z, disabled compromised account, blocked attacker connection. Access stopped.

## Scope

- **Patient Records:** ~1,847 files from 180–300 patients (April 15–18 dates)
- **Data:** Lab results, ER admission notes, clinical progress notes with patient names/IDs
- **Systems:** 4 clinical workstations + 1 file server accessed
- **Staff:** 1 account (jdoe, scheduler) compromised; account disabled

## Regulatory Obligation

**HIPAA Breach Notification required.** Unauthorized access + data transmission = legal obligation to notify patients, HHS, and media (if >500 patients).

## Completed Actions
- Systems isolated from network (20:35Z)
- Compromised account disabled (20:50Z)
- Attacker connection blocked (20:55Z)
- Forensic evidence secured
- File server operational; patient care unaffected

## In Progress
1. Identify affected patients (by April 21)
2. Draft patient notifications (by April 22)
3. File with HHS (by May 20)
4. Remove malware, rebuild systems (April 21–23)

## Patient Care Impact
**None.** File server works. No ransomware executed. Clinical staff operational.

**Next Update:** April 22, 14:00Z — Patient count, notification timeline

**Dr. Patricia Morales, CISO | April 21, 06:45 UTC**
