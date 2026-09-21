# Email Evidence Batch

## Summary Verdict Table

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| **E1** | SPAM | LEGITIMATE | High (99%) | SPF, DKIM, and DMARC all PASS for `healthcare-education-weekly.com`; sent via standard MailChimp infrastructure (`X-Mailer: MailChimp Mailer v12.4`); valid list-unsubscribe headers. | None required (allow/deliver; guide user on opt-in newsletter management if unwanted). |
| **E2** | PHISHING-TARGETED | PHISHING-TARGETED | High (100%) | SPF/DMARC FAIL; sent via PHPMailer from budget host (`91.234.99.107`); lookalike domain (`meddefense-portal.com`); targeted nurse Diane Marsh with urgent portal lockout pretext. | **IMMEDIATE:** Isolate WS-NURSE-04 (`10.10.2.15`), revoke session tokens/reset password for `dmarsh`, block domain/IP on firewall & DNS, audit AD & EHR logs. |
| **E3** | PHISHING-OPPORTUNISTIC | PHISHING-OPPORTUNISTIC | High (98%) | SPF/DKIM pass for domain `outlook-protection.com` (spoofed M365 security branding); sent via PHPMailer (`51.38.42.17`); generic "unusual sign-in" credential harvesting lure. | Block `outlook-protection.com` and IP `51.38.42.17`, purge email batch from Exchange, verify `rmendez` did not interact with link. |
| **E4** | LEGITIMATE | LEGITIMATE | High (100%) | Sent internally from Exchange Hub (`10.10.1.15`); valid domain DKIM (`meddefense.com`); standard IT password change notification referencing internal `.local` URLs; explicitly warns against clicking external password links. | No action required (legitimate internal SOC broadcast). |
| **E5** | SPAM | PHISHING-TARGETED | High (98%) | SPF softfail / DMARC FAIL; sent via PHPMailer from `185.176.43.22`; typosquatted supplier domain (`medequip-supplies.net`); targeted AP specialist Angela Rivera; PDF attachment contains embedded credential harvesting payment portal link. | Block domain `medequip-supplies.net`, purge email, alert AP team to reject invoice INV-2026-04891, confirm Angela Rivera did not click embedded PDF URI. |
| **E6** | SPAM | SPAM | High (100%) | High SpamAssassin score (9.8/5.0); DMARC fail/quarantine; raw IP URL (`http://203.0.113.228/shop`); bulk pharmaceutical spam headers from untrusted IP (`203.0.113.228`). | Retain in quarantine / purge; no user account compromise risk. |
| **E7** | PHISHING-TARGETED | PHISHING-TARGETED | High (100%) | SPF/DMARC FAIL; sent via PHPMailer on DigitalOcean VPS (`164.90.218.73`); lookalike HR domain (`meddefense-benefits.org`); targeted billing clerk Linda Patterson with fake open enrollment deadline pretext (matches HC3 alert). | Block `meddefense-benefits.org` and IP `164.90.218.73`, purge message, confirm Linda Patterson did not submit credentials on fake portal. |
| **E8** | LEGITIMATE | LEGITIMATE | High (100%) | SPF, DKIM, and DMARC pass for official government domain `hhs.gov` (`134.174.47.82`); official threat alert from HHS HC3 describing the exact campaign patterns observed in E2, E5, and E7. | Process advisory IOCs into SOC firewall/SIEM detection rules; share advisory with regional ISAC partners. |

## Detailed Analysis of Classification Shifts

### Email 1 (E1): SPAM $\rightarrow$ LEGITIMATE
* **Initial Surface Impression:** Reported as potential spam by end user / initial triage due to automated newsletter distribution headers (`Precedence: bulk`).
* **Deeper Technical Analysis:** 
  * Header analysis confirms complete authentication alignment: SPF (`pass`), DKIM (`pass` signed by `healthcare-education-weekly.com`), and DMARC (`pass`).
  * Originating IP (`198.51.100.42`) matches MailChimp bulk email infrastructure (`X-MC-User: c3f8b1a4e7`).
  * Includes standard `List-Unsubscribe` header and RFC-compliant unsubscribe link matching recipient history.
* **Verdict Reason:** E1 is a legitimate opt-in educational publication, not malicious or spam.

### Email 5 (E5): SPAM $\rightarrow$ PHISHING-TARGETED
* **Initial Surface Impression:** Flagged initially as generic commercial spam or misdirected invoice inquiry.
* **Deeper Technical Analysis:**
  * Sender uses typosquatted domain `medequip-supplies.net` (impersonating a medical equipment supplier).
  * Authentication checks failed (SPF `softfail`, DKIM `none`, DMARC `fail`).
  * Sent using PHPMailer 6.6.0 on a budget European VPS (`185.176.43.22`).
  * Specific role-based targeting directed at Angela Rivera in Accounts Payable (`arivera@meddefense.com`) demanding USD 24,716.38.
  * PDF payload (`INV-2026-04891.pdf`) contains an embedded PDF annotation link (`/Subtype /Link /URI (https://medequip-supplies.net/invoices/pay...)`) designed to bypass standard email gateway link scanners.
  * Perfectly matches HC3 Alert (E8) criteria for targeted supplier invoice lures.
* **Verdict Reason:** Reclassified from generic spam to a high-risk, targeted invoice/financial phishing attack.

## Triage Accuracy Assessment

* **Total Emails Evaluated:** 8
* **Correct Initial Classifications:** 6 (E2, E3, E4, E6, E7, E8)
* **Incorrect Initial Classifications:** 2 (E1, E5)
* **Initial Triage Accuracy Rate:** **75%** ($\frac{6}{8}$)

### Assessment Summary
Initial surface triage successfully identified obvious malicious indicators (E2, E3, E7), internal legitimate broadcasts (E4), bulk spam (E6), and official government advisories (E8). However, initial triage was susceptible to:
1. **False Positives on Bulk Mail (E1):** Misclassifying legitimate opt-in bulk communications as spam.
2. **False Negatives on BEC/Invoice Phishing (E5):** Underestimating targeted financial spear-phishing attempts that utilize PDF attachments and typosquatted vendor domains.

## Recommended SOC Actions by Category

### Immediate Incident Response (Active Click Identified - E2)
1. **Host Containment:** Network isolate workstation `WS-NURSE-04` (`10.10.2.15`).
2. **Identity Protection:** Revoke all Active Directory and Azure AD/M365 session tokens for `dmarsh@meddefense.com`; initiate mandatory password reset.
3. **Log Audit:** Review AD domain controller logs, VPN gateway logs, and EHR portal authentication logs for IP `91.234.99.107` or associated proxy traffic starting at `2026-04-14 15:02:33 CDT`.

### Perimeter Threat Blocking (E2, E3, E5, E7)
Block the following malicious domains and IP addresses at the perimeter firewall, web proxy, and DNS sinkhole:
* **Domains:**
  * `meddefense-portal.com`
  * `outlook-protection.com`
  * `medequip-supplies.net`
  * `meddefense-benefits.org`
* **IP Addresses:**
  * `91.234.99.107`
  * `51.38.42.17`
  * `185.176.43.22`
  * `164.90.218.73`

### Mail Gateway Remediation (E2, E3, E5, E6, E7)
1. Execute Exchange PowerShell search-and-destroy (`Search-Mailbox` / `New-ComplianceSearch`) across all organization mailboxes for messages originating from the four malicious domains.
2. Ensure Proofpoint/email gateway rules strictly enforce quarantine/rejection on DMARC failures for newly registered domains.
