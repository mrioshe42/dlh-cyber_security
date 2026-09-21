# Verdict Matrix

## Summary Verdict Table

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| **E1** | SPAM | SPAM | High (99%) | Bulk newsletter distribution headers (`Precedence: bulk`); valid SPF/DKIM/DMARC; unsolicited commercial content. | Retain in user spam folder or process RFC list-unsubscribe headers. |
| **E2** | PHISHING-TARGETED | PHISHING-TARGETED | High (100%) | SPF/DMARC FAIL; sending IP `91.234.99.107` (PHPMailer); lookalike domain `meddefense-portal.com`; targeted Nurse Diane Marsh with urgent portal lockout pretext. | **IMMEDIATE:** Isolate `WS-NURSE-04` (`10.10.2.15`), revoke sessions and reset password for `dmarsh`, block domain/IP on perimeter, audit directory and EHR logs. |
| **E3** | PHISHING-OPPORTUNISTIC | PHISHING-OPPORTUNISTIC | High (98%) | SPF/DKIM pass on lookalike domain `outlook-protection.com`; sending IP `51.38.42.17` (PHPMailer); generic M365 unusual sign-in credential harvesting lure. | Block domain `outlook-protection.com` and IP `51.38.42.17`, purge email batch from Exchange, confirm `rmendez` did not interact with link. |
| **E4** | LEGITIMATE | LEGITIMATE | High (100%) | Internal Exchange Hub (`10.10.1.15`); valid domain DKIM (`meddefense.com`); standard IT password change notification referencing internal `.local` paths. | No action required (legitimate internal broadcast). |
| **E5** | SPAM | PHISHING-TARGETED | High (98%) | SPF softfail / DMARC FAIL; sending IP `185.176.43.22` (PHPMailer); typosquatted vendor domain `medequip-supplies.net`; targeted AP specialist Angela Rivera; PDF payload (`INV-2026-04891.pdf`) contains embedded credential-harvesting payment link. | Block domain `medequip-supplies.net`, purge email, alert AP team to reject invoice `INV-2026-04891`, confirm Angela Rivera did not open embedded PDF link. |
| **E6** | SPAM | SPAM | High (100%) | High SpamAssassin score (9.8/5.0); DMARC fail/quarantine; raw IP URL (`http[:]//203.0.113.228/shop`); bulk pharmaceutical spam headers from untrusted IP (`203.0.113.228`). | Retain in mail gateway quarantine / purge; no account compromise risk. |
| **E7** | PHISHING-TARGETED | PHISHING-TARGETED | High (100%) | SPF/DMARC FAIL; sending IP `164.90.218.73` (DigitalOcean VPS); lookalike HR domain `meddefense-benefits.org`; targeted billing clerk Linda Patterson with open enrollment deadline pretext. | Block domain `meddefense-benefits.org` and IP `164.90.218.73`, purge email, verify Linda Patterson did not submit credentials on fake portal. |
| **E8** | LEGITIMATE | LEGITIMATE | High (100%) | SPF, DKIM, and DMARC pass for official government domain `hhs.gov` (`134.174.47.82`); official threat alert from HHS HC3 describing sector-wide phishing patterns. | Process advisory IOCs into firewall/SIEM detection rules; share advisory with internal security operations team. |

## Detailed Analysis of Classification Shifts

### Email 5 (E5): Initial Triage SPAM $\rightarrow$ Final Verdict PHISHING-TARGETED
* **Initial Surface Impression:** Flagged during initial triage as low-priority commercial spam due to external commercial billing pretexts.
* **Technical Evidence:** 
  * Sender used typosquatted vendor domain `medequip-supplies.net` impersonating a medical equipment provider.
  * Authentication failed (SPF `softfail`, DKIM `none`, DMARC `fail`).
  * Sent via PHPMailer on external hosting IP `185.176.43.22`.
  * Role-based targeting directed specifically at Angela Rivera in Accounts Payable (`arivera@meddefense.com`) demanding payment for USD 24,716.38.
  * Attachment `INV-2026-04891.pdf` contained an active embedded link annotation (`/Subtype /Link /URI (https[:]//medequip-supplies[.]net/invoices/pay...)`) designed to route recipients to an external credential-harvesting site.
* **Verdict Reason:** Reclassified from generic spam to a high-risk **PHISHING-TARGETED** attack aimed at financial credential theft and fraudulent payment processing.

## Triage Accuracy Assessment

* **Total Emails Evaluated:** 8
* **Correct Initial Classifications:** 7 (E1, E2, E3, E4, E6, E7, E8)
* **Incorrect Initial Classifications:** 1 (E5)
* **Initial Triage Accuracy Rate:** **87.5%** (7 out of 8)

### Assessment Summary
Initial triage successfully identified bulk spam (E1, E6), obvious credential-harvesting lures (E2, E3, E7), internal broadcasts (E4), and official government threat advisories (E8). However, initial surface triage exhibited one key limitation:
* **Underestimating Vendor Impersonation (E5):** Misjudging targeted invoice phishing with embedded PDF links as routine commercial spam due to surface-level invoice wording.

## Summary of Recommended Actions by Threat Category

### Active Click Response (Email 2)
1. Network isolate workstation `WS-NURSE-04` (`10.10.2.15`).
2. Revoke active session tokens and force an Active Directory/M365 password reset for `dmarsh@meddefense.com`.
3. Audit Active Directory domain controller logs, Azure AD sign-in logs, and EHR access logs for activity originating from `91.234.99.107` or associated proxy infrastructure following `2026-04-14 15:02:33 CDT`.

### Perimeter Threat Indicators to Block
Block the following malicious domains and IP addresses at the firewall, secure web gateway, and DNS sinkhole:
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

### Mail Gateway Remediation
1. Conduct Exchange compliance purges (`Search-Mailbox` / `New-ComplianceSearch`) across all mailboxes to delete instances of E2, E3, E5, E6, and E7.
2. Verify mail gateway transport rules enforce quarantine or rejection actions for messages failing DMARC from external lookalike domains.
