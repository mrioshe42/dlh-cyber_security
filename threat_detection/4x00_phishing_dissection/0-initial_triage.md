# Initial Email Triage Report

**Date:** 2026-04-17  
**Analyst:** Security Operations Center  
**Scope:** Triage of 8 raw `.eml` files from MedDefense Health Systems evidence batch  

---

## Rapid Triage Matrix

| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|---|---|---|---|---|---|---|---|---|
| **E1** | `newsletter@healthcare-education-weekly.com` | Your April newsletter: Medication reconciliation best practices | pass | pass | pass | LEGITIMATE | P4-LOW | Valid authentication (MailChimp). Standard educational newsletter sent to opt-in user list. |
| **E2** | `noreply@meddefense-portal.com` | ACTION REQUIRED: Portal re-verification needed within 24 hours | fail | none | fail | SUSPICIOUS | P1-URGENT | **Confirmed user click by Diane Marsh (WS-NURSE-04).** Lookalike domain, PHPMailer source, fake portal re-verification lure. |
| **E3** | `security@outlook-protection.com` | Unusual sign-in activity detected on your Microsoft 365 account | pass | pass | pass | SUSPICIOUS | P2-HIGH | Brand impersonation (Microsoft). Passed auth because attacker owns the domain. Credential harvesting link targeting M365 accounts. |
| **E4** | `it-announcements@meddefense.com` | Reminder: Quarterly password change window opens April 20 | pass | pass | pass | LEGITIMATE | P4-LOW | Internal communication originating from internal Exchange server (10.10.1.15). Explicitly directs staff to internal intranet. |
| **E5** | `invoices@medequip-supplies.net` | Invoice INV-2026-04891, Payment required within 7 days | softfail | none | fail | SUSPICIOUS | P2-HIGH | Financial invoice lure ($24,716.38) sent via PHPMailer. PDF attachment contains embedded link to external payment portal. |
| **E6** | `deals@canadian-pharma-discount.org` | 90% OFF Viagra, Cialis, Xanax, No prescription needed!!! | softfail | none | fail | SPAM | P4-LOW | High spam score (9.8). Unsolicited bulk email containing direct IP links (`203.0.113.228`). |
| **E7** | `hr-notifications@meddefense-benefits.org` | Open Enrollment closes TOMORROW, action required | fail | none | fail | SUSPICIOUS | P2-HIGH | HR lure targeting billing personnel. Lookalike domain (`meddefense-benefits.org`), failed authentication, sent via budget VPS IP. |
| **E8** | `HC3@hhs.gov` | [HC3 ALERT — TLP:CLEAR] Active phishing campaign targeting regional healthcare | pass | pass | pass | LEGITIMATE | P3-MEDIUM | Official threat advisory from HHS HC3 (`hhs.gov`). Describes tactics matching E2, E5, and E7. |

---

## Triage Summary

- **SPAM:** 1 email (E6)
- **SUSPICIOUS:** 4 emails (E2, E3, E5, E7)
- **LEGITIMATE:** 3 emails (E1, E4, E8)
- **Highest priority:** E2 (`P1-URGENT`) Confirmed link interaction by Diane Marsh on workstation `WS-NURSE-04` approximately 36 hours ago. Immediate host containment and credential reset required.