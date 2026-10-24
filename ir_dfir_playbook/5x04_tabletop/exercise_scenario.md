# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 2026-10-24
**Classification:** Internal - Exercise Use Only
**Facilitator:** massimo
**Scenario version:** 1.0 
**Participants:** Dr. Patricia Morales (CISO), James Chen (SOC Lead / IR Commander), Sarah Park (IT Director), Robert Kim (Infrastructure Lead), Mike Torres (Network Engineer), Helena Reyes (General Counsel), Marcus Webb (Communications Director), Lisa Tanaka (Vendor Risk)


## Organization background

MedDefense Health Systems is a non-profit HIPAA Covered Entity in Portland, OR, with three sites: West Campus (outpatient and specialty clinics, 58,000 visits a year), Main Hospital (384 beds, 17,400 admissions) and North Site (112-bed long-term care and rehab), and about 180,000 active patient records in Epic. All three sites run outpatient scheduling, pre-registration and insurance eligibility checks through Nexus Patient Scheduling, about 3,500 patient interactions a week, and the board has committed to a 24-hour RTO for scheduling. The last tabletop (2025-08-14) covered ransomware; MedDefense has never exercised a supply-chain scenario and has never run a joint exercise with Nexus.

## Vendor background

| | |
|---|---|
| **Vendor** | Nexus Health Technologies, Inc. (Austin, TX). Multi-tenant SaaS on AWS (`us-east-1`, `us-west-2`). MedDefense customer since 2023-08-14. |
| **Data held** | ePHI: patient demographics, insurance information, appointment and wait-list data. No clinical charting. |
| **Epic integration** | HL7 FHIR R4 over HTTPS. Outbound, MedDefense calls `https://fhir.nexushealth.io/v1/` with scheduling requests, demographics and eligibility queries. Inbound, Nexus calls the EHR ingest endpoint `https://ehr-ingest.meddefense.local/nexus-inbound/` over a site-to-site IPsec tunnel with confirmed appointments, wait-list notices and **automated schedule updates**. Auth is OAuth2 client credentials, with short-lived tokens bound to `svc-nexus-prod`. |
| **On-prem footprint** | `nexus-agent` on `SCHED-SVR-01` (Main). Nexus pushes updates **automatically**, and the agent accepts any package signed with the "Nexus Health Technologies, Inc." code-signing certificate. |
| **Subprocessors** | AWS, Twilio (SMS reminders), SendGrid (email reminders) |
| **BAA** | In force since 2023-08-01, amended 2025-05-20 for the HIPAA Security Rule 2025 update. Nexus must notify MedDefense of a breach **within 24 hours of its discovery**, deliver an annual SOC 2 Type II report, and return or destroy PHI on termination. |
| **SLA** | There is no uptime or incident-response SLA on file. The only time-bound commitments are the BAA's 24-hour breach notice and MedDefense's own 24-hour RTO for scheduling. |
| **Last vendor review** | 2025-11-14, by Lisa Tanaka. Covered the SOC 2 Type II (2025-10) report, the pentest summary and the incident questionnaire. Open findings: (1) the update channel relies on code-signing certificate validation alone, with no client-side hash pin; (2) there is no bill of materials for the agent's third-party npm dependencies; (3) the incident communication path is documented at the contact level but has never been tested jointly. Next review is due 2026-11-14. |
| **Nexus contacts** | 24x7 SecOps: +1 512 555 0184, soc@nexushealth.io · CISO Marcus Oduya: security@nexushealth.io · Counsel Evelyn Park: legal@nexushealth.io · AE Priya Natarajan: priya.natarajan@nexushealth.io |

## Opening situation

**T+0.** Forty-five minutes ago the SOC flagged unusual outbound traffic from the scheduling server `SCHED-SVR-01` to an unknown external IP address. The on-call analyst pulled EDR for the host, and it shows the same outbound connection repeating every four hours. The ticket is now with James Chen as IR Commander.

### Known facts

| Fact | Detail |
|---|---|
| Traffic alert | Outbound traffic from `SCHED-SVR-01` to an unknown external IP, raised 45 minutes ago |
| Hosts | `SCHED-SVR-01` (Main) is the only Nexus agent host on record. No one has checked whether West Campus or North Site run the agent too. |
| EDR alert | Periodic outbound connections from `SCHED-SVR-01` at fixed four-hour intervals |

Nothing else is known. Specifically, the team does not yet know when the pattern started, which process makes the connection, who owns the IP, whether data has left, whether records have changed, or whether Nexus knows.

### Patient safety

Nexus writes confirmed appointments, wait-list notices and schedule updates into Epic automatically, and it reminds patients through Twilio and SendGrid. If `SCHED-SVR-01` is compromised, **any appointment created, moved or cancelled during the compromise window may have been modified**, and no one knows when that window opened. A patient who was silently cancelled does not come in. An altered pre-registration record breaks the insurance eligibility check. At about 3,500 interactions a week, each day of exposure brings roughly 500 patient interactions into scope.

### HIPAA tension

Nexus is a Business Associate holding MedDefense ePHI. The BAA gives Nexus 24 hours from *its own* discovery to notify MedDefense, but here MedDefense may be the one discovering it. Under the Breach Notification Rule, MedDefense's clock starts on the first day it knew of the breach, or would have known with reasonable diligence (45 CFR 164.404(a)(2)). If Nexus counts as MedDefense's agent, what Nexus knew counts as known to MedDefense. As the Covered Entity, MedDefense owes notice to individuals within 60 days. If more than 500 residents of a state are affected, it also owes notice to HHS and the media (164.406, 164.408). The Oregon Consumer Information Protection Act (ORS 646A.600) applies, and so does the Washington My Health My Data Act for WA patients seen at West Campus. **Did the clock start 45 minutes ago, or does it start when Nexus confirms?**

### Decisions with no clear right answer

1. **Is a signed update still trustworthy?** The update channel did exactly what it was built to do: it accepted code signed with Nexus's own certificate. If MedDefense pauses auto-update, it loses the vendor's fix path when Nexus ships a clean build. If it keeps auto-update on, it accepts the next signed package from the same pipeline. Does a valid signature make the next Nexus update more trustworthy or less?
2. **Isolate or keep booking?** Pulling `SCHED-SVR-01` or the IPsec tunnel stops the beacon and stops writes into Epic. It also halts scheduling at all three sites and tells whoever is on the host that they have been seen. Keeping it up preserves evidence and operations, but suspect appointment data keeps flowing into Epic, and the 24-hour scheduling RTO applies either way.
3. **When and how to call Nexus?** The BAA puts the notification duty on Nexus, and the contact path has never been tested. Calling the 24x7 SecOps line now may be the fastest way to get answers. It may also alert an attacker who is inside Nexus. Waiting for more evidence uses up hours of a HIPAA clock that may already be running.
