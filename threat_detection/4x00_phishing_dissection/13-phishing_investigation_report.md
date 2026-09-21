# The Investigation Report

**Document ID:** INC-2026-0417-RPT  
**Target Organization:** MedDefense Health Systems  
**Lead Investigator:** SOC Analyst / Incident Response Team  
**Date of Report:** April 17, 2026  
**Status:** Complete - Pending Executive & Technical Distribution

## 1. Executive Summary

Between April 14 and April 16, 2026, MedDefense Health Systems was targeted by a coordinated credential-harvesting and financial fraud phishing campaign impersonating internal IT, Human Resources, and external healthcare vendors. A total of eight suspicious emails were collected and analyzed, revealing that three external messages were directly linked to a single threat actor utilizing shared sending infrastructure and role-tailored social engineering lures. A threat advisory issued by the Health Sector Cybersecurity Coordination Center (HC3) independently confirmed that this campaign is actively targeting regional healthcare entities. One nurse clicked a credential-harvesting link within a fake IT portal notice; immediate containment and credential revocation protocols have been initiated to prevent unauthorized system access. Immediate technical remediation is underway to block identified malicious domains, revoke impacted accounts, and tighten email gateway security controls.


## 2. Investigation Timeline

| Date & Time (CDT) | Event Description | Source / Target |
| :--- | :--- | :--- |
| **2026-04-14 07:22:14** | Email 1 Delivered: "Your April newsletter: Medication reconciliation best practices" | Newsletter service $\rightarrow$ Jennifer Moore (`jmoore@meddefense[.]com`) |
| **2026-04-14 14:47:52** | Email 2 Delivered: "ACTION REQUIRED: Portal re-verification needed within 24 hours" | Malicious Infrastructure $\rightarrow$ Diane Marsh (`dmarsh@meddefense[.]com`) |
| **2026-04-14 15:02:33** | **Security Incident:** Diane Marsh clicks phishing link in Email 2 | Workstation `WS-NURSE-04` (IP: `10[.]10[.]2[.]15`) |
| **2026-04-15 09:13:44** | Email 3 Delivered: "Unusual sign-in activity detected on your Microsoft 365 account" | Malicious Infrastructure $\rightarrow$ Rafael Mendez (`rmendez@meddefense[.]com`) |
| **2026-04-15 10:00:12** | Email 4 Delivered: Internal IT Announcement re: Password change window | Internal Exchange Hub $\rightarrow$ Clinical Staff (`staff-clinical@meddefense[.]com`) |
| **2026-04-16 08:47:02** | Email 8 Delivered: HC3 Preliminary Advisory (TLP:CLEAR) re: Regional Phishing Campaign | HHS HC3 $\rightarrow$ MedDefense SOC (`soc-alerts@meddefense[.]com`) |
| **2026-04-16 11:28:39** | Email 5 Delivered: "Invoice INV-2026-04891 - Payment required within 7 days" | Malicious Infrastructure $\rightarrow$ Angela Rivera (`arivera@meddefense[.]com`) |
| **2026-04-16 13:04:22** | Email 6 Delivered: "90% OFF Viagra, Cialis, Xanax - No prescription needed!!!" (Quarantined) | Bulk Spam Service $\rightarrow$ P. White (`pwhite@meddefense[.]com`) |
| **2026-04-16 15:22:07** | Email 7 Delivered: "Open Enrollment closes TOMORROW - action required" | Malicious Infrastructure $\rightarrow$ Linda Patterson (`lpatterson@meddefense[.]com`) |
| **2026-04-17 09:15:00** | Email evidence batch (~57-hour window) compiled by Network Engineering | Mike Torres (Network Engineer) |

### Investigation Scope
The scope of this investigation encompasses all eight raw SMTP email messages collected between April 14, 2026, 07:22 CDT and April 16, 2026, 15:22 CDT, system and proxy logs associated with workstation `WS-NURSE-04` (`10[.]10[.]2[.]15`), and external threat intelligence indicators provided in HC3 Advisory `HC3-2026-PRELIM-001`.

## 3. Email-by-Email Analysis

### Email 1 (E1)
* **Sender:** `"Healthcare Education Weekly" <newsletter@healthcare-education-weekly[.]com>`
* **Recipient:** Jennifer Moore (`jmoore@meddefense[.]com`)
* **Subject:** *Your April newsletter: Medication reconciliation best practices*
* **Verdict:** Legitimate
* **Classification:** Benign Educational / Marketing Newsletter
* **Confidence Level:** High
* **Key Evidence:** Sender IP `198[.]51[.]100[.]42` successfully passed SPF, DKIM (`header.d=healthcare-education-weekly[.]com`), and DMARC (`pass`). Includes valid MailChimp headers (`X-Mailer: MailChimp Mailer v12.4`), standardized unsubscribe headers, and standard bulk precedence tags.

### Email 2 (E2)
* **Sender:** `"MedDefense IT Security" <noreply@meddefense-portal[.]com>`
* **Recipient:** Diane Marsh (`dmarsh@meddefense[.]com`)
* **Subject:** *ACTION REQUIRED: Portal re-verification needed within 24 hours*
* **Verdict:** Malicious
* **Classification:** Credential Harvesting Phishing (Lookalike Domain / Brand Impersonation)
* **Confidence Level:** High
* **Key Evidence:** Originates from unauthorized IP `91[.]234[.]99[.]107` via `PHPMailer 6.6.0`. Fails SPF (`fail`), DKIM (`none`), and DMARC (`fail`). Spoofs internal IT branding using lookalike domain `meddefense-portal[.]com`. Contains a personalized tracking URL (`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`) designed to capture clinical portal credentials under threat of 24-hour lockout.

### Email 3 (E3)
* **Sender:** `"Microsoft Account Protection" <security@outlook-protection[.]com>`
* **Recipient:** Rafael Mendez (`rmendez@meddefense[.]com`)
* **Subject:** *Unusual sign-in activity detected on your Microsoft 365 account*
* **Verdict:** Malicious
* **Classification:** Credential Harvesting Phishing (Typosquat / M365 Impersonation)
* **Confidence Level:** High
* **Key Evidence:** Employs `PHPMailer 6.6.0` from host IP `51[.]38[.]42[.]17`. Uses typosquatted domain `outlook-protection[.]com` with attacker-configured SPF/DKIM authentication to pass gateway checks. Employs a simulated security alert lure ("Lagos, Nigeria sign-in attempt") directing the recipient to a credential harvesting landing page (`hxxps://outlook-protection[.]com/verify`).

### Email 4 (E4)
* **Sender:** `"MedDefense IT Announcements" <it-announcements@meddefense[.]com>`
* **Recipient:** Clinical Staff (`staff-clinical@meddefense[.]com`)
* **Subject:** *Reminder: Quarterly password change window opens April 20*
* **Verdict:** Legitimate
* **Classification:** Official Internal Broadcast Communication
* **Confidence Level:** High
* **Key Evidence:** Originated internally from Exchange Hub (`10[.]10[.]1[.]15`). Passes internal SPF, DKIM (`selector1`), and DMARC. Signed by SOC Lead James Chen. Explicitly instructs users to access the password portal via the internal network/VPN (`portal[.]meddefense[.]local/password`) and contains explicit security guidance: *"IT will never email you a link to change your password."*

### Email 5 (E5)
* **Sender:** `"MedEquip Supplies Billing" <invoices@medequip-supplies[.]net>`
* **Recipient:** Angela Rivera (`arivera@meddefense[.]com`)
* **Subject:** *Invoice INV-2026-04891 - Payment required within 7 days*
* **Verdict:** Malicious
* **Classification:** Financial Fraud / Credential Harvesting Phishing
* **Confidence Level:** High
* **Key Evidence:** Sent via `PHPMailer 6.6.0` from host IP `185[.]176[.]43[.]22`. Fails SPF (`softfail`), DKIM (`none`), and DMARC (`fail`). Targets Accounts Payable with a fraudulent USD $24,716.38 invoice. Contains embedded links and an attached PDF (`INV-2026-04891.pdf`) featuring `/Subtype /Link` annotations directing to `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`.

### Email 6 (E6)
* **Sender:** `"Canadian Pharma Discounts" <deals@canadian-pharma-discount[.]org>`
* **Recipient:** P. White (`pwhite@meddefense[.]com`)
* **Subject:** *90% OFF Viagra, Cialis, Xanax - No prescription needed!!!*
* **Verdict:** Malicious / Spam
* **Classification:** Unsolicited High-Volume Commercial / Pharmaceutical Spam
* **Confidence Level:** High
* **Key Evidence:** High spam score (`X-Spam-Score: 9.8`, triggering `BODY_8BITS`, `DRUGS_ERECTILE`, `NUMERIC_HTTP_ADDR`). Fails DMARC (`fail action=quarantine`). Sent via `XPedia Bulk Mailer 4.2` from `203[.]0[.]113[.]228`, directing users to a raw IP hyperlink (`hxxp://203[.]0[.]113[.]228/shop?ref=pwhite`). Quarantined by Proofpoint.

### Email 7 (E7)
* **Sender:** `"MedDefense HR Benefits" <hr-notifications@meddefense-benefits[.]org>`
* **Recipient:** Linda Patterson (`lpatterson@meddefense[.]com`)
* **Subject:** *Open Enrollment closes TOMORROW - action required*
* **Verdict:** Malicious
* **Classification:** Credential Harvesting Phishing (HR / Benefits Impersonation)
* **Confidence Level:** High
* **Key Evidence:** Sent via `PHPMailer 6.6.0` from IP `164[.]90[.]218[.]73`. Fails SPF (`fail`), DKIM (`none`), and DMARC (`fail`). Targets Billing/HR personnel using lookalike domain `meddefense-benefits[.]org`. Employs high-urgency social engineering threatening benefit coverage lapse unless re-enrolled immediately via `hxxps://meddefense-benefits[.]org/enroll`.

### Email 8 (E8)
* **Sender:** `"HC3 Sector Alerts" <HC3@hhs[.]gov>`
* **Recipient:** MedDefense SOC (`soc-alerts@meddefense[.]com`)
* **Subject:** `[HC3 ALERT - TLP:CLEAR] Active phishing campaign targeting regional healthcare`
* **Verdict:** Legitimate
* **Classification:** Official Government Threat Intelligence Advisory
* **Confidence Level:** High
* **Key Evidence:** Sent from official HHS infrastructure (`134[.]174[.]47[.]82`). Fully authenticated via SPF, DKIM (`header.d=hhs.gov`), and DMARC. Issued under advisory reference `HC3-2026-PRELIM-001`, warning regional healthcare SOCs of an active, role-tailored phishing campaign matching observed indicators.

## 4. Campaign Analysis

### Infrastructure & Operational Correlation (Emails 2, 5, and 7)
Emails 2, 5, and 7 constitute a single, highly coordinated phishing campaign orchestrated by a common threat actor. The connection is established through four distinct technical and operational overlaps:
1. **Technical Infrastructure & Mailer Footprint:** All three emails were generated using `PHPMailer 6.6.0` running on budget VPS hosting provider IP spaces (`91[.]234[.]99[.]107`, `185[.]176[.]43[.]22`, and `164[.]90[.]218[.]73`).
2. **Domain Registration Strategy:** All three attack vectors utilize newly registered lookalike domains (< 30 days old) combining the MedDefense organization name or supplier identity with functional keywords (`meddefense-portal[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`).
3. **Authentication Signature:** All three messages lack DKIM signatures (`dkim=none`) and fail SPF/DMARC authentication, relying on permissive gateway configuration (`action=none`) for delivery.
4. **Role-Tailored Social Engineering Pretexts:** The threat actor performed organizational reconnaissance to align lures with recipient job responsibilities:
   * **E2 (Clinical):** Staff portal re-verification lure sent to Nurse Diane Marsh.
   * **E5 (Accounts Payable):** Supplier medical invoice lure sent to AP Lead Angela Rivera.
   * **E7 (Billing / HR):** Open enrollment deadline lure sent to Billing staff Linda Patterson.

### Alignment with Threat Intelligence (Email 8)
Email 8 (HC3 Advisory `HC3-2026-PRELIM-001`) serves as critical external validation for the internal campaign hypothesis. The advisory confirms that healthcare organizations across the Midwest region are facing targeted phishing employing:
* Newly-registered `.com`/`.net`/`.org` domains containing keywords like `portal`, `benefits`, `supplies`, or `login`.
* `PHPMailer` sending infrastructure hosted on cheap VPS platforms.
* Urgency-driven pretexts (24–48 hour cutoffs, service suspensions).
* Role-specific targeting (clinical, billing, AP).

This corroborates that MedDefense is not experiencing isolated spam, but is an active target in a regional cybercrime credential harvesting operation.

### Interpretation of Email 3
Email 3 (`outlook-protection[.]com`) shares structural indicators with the primary campaign-specifically the use of `PHPMailer 6.6.0` and a high-urgency credential harvesting objective. However, unlike E2, E5, and E7, the threat actor properly configured SPF and DKIM records for `outlook-protection[.]com`, allowing E3 to pass email authentication checks. E3 should be interpreted as a **broad-spectrum identity harvesting wave** executed by the same threat actor to capture enterprise Microsoft 365 credentials alongside custom organizational portal logins.

## 5. Click Incident Assessment

### Incident Summary
* **User:** Diane Marsh (`dmarsh@meddefense[.]com`)
* **Role / System:** Staff Nurse (`WS-NURSE-04`, IP: `10[.]10[.]2[.]15`)
* **Delivery Time:** April 14, 2026 at 14:47:52 CDT
* **Click Timestamp:** April 14, 2026 at 15:02:33 CDT (~14 minutes post-delivery)
* **Target URL:** `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`

### Scope of Evidence & Deterministic Bounds
* **What CAN be concluded:** Diane Marsh interacted with the phishing payload by clicking the unique, tokenized link embedded within E2. The request was dispatched from `WS-NURSE-04` (`10[.]10[.]2[.]15`) to the malicious domain `meddefense-portal[.]com`.
* **What CANNOT be concluded:** The raw SMTP email batch alone cannot confirm whether Diane Marsh entered domain credentials on the phishing landing page, whether secondary MFA tokens were intercepted, whether malicious scripts/exploits were executed via the browser, or whether active session tokens were compromised.

### Immediate Containment Protocols
1. **Identity Containment:** Revoke all active M365 and domain session tokens for `dmarsh@meddefense[.]com` and perform a forced password reset. Enforce re-registration of MFA methods.
2. **Endpoint Isolation:** Disconnect workstation `WS-NURSE-04` (`10[.]10[.]2[.]15`) from the local network/VLAN to prevent potential lateral movement.
3. **Forensic Triage:**
   * Extract web browser history, cache, and HTTP POST request logs from `WS-NURSE-04` for the timestamp `2026-04-14 15:02:33 CDT` to verify parameter submission.
   * Query perimeter web proxy/DNS logs for subsequent outbound traffic from `10[.]10[.]2[.]15` to `91[.]234[.]99[.]107` or related IPs.
   * Inspect Active Directory and M365 sign-in logs for successful authentication events originating from `91[.]234[.]99[.]107` or anomalous geographic locations post-click.

## 6. IOC Summary

| Category | Indicator / Value | Context / Association |
| :--- | :--- | :--- |
| **Domain** | `meddefense-portal[.]com` | Campaign Lookalike Domain (E2 - IT Portal) |
| **Domain** | `outlook-protection[.]com` | Campaign Typosquat Domain (E3 - Microsoft 365) |
| **Domain** | `medequip-supplies[.]net` | Campaign Lookalike Domain (E5 - Invoice Fraud) |
| **Domain** | `meddefense-benefits[.]org` | Campaign Lookalike Domain (E7 - HR Benefits) |
| **Domain** | `canadian-pharma-discount[.]org` | Spam Domain (E6) |
| **IP Address** | `91[.]234[.]99[.]107` | E2 Sending Server / Hosting IP |
| **IP Address** | `51[.]38[.]42[.]17` | E3 Sending Server / Hosting IP |
| **IP Address** | `185[.]176[.]43[.]22` | E5 Sending Server / Hosting IP |
| **IP Address** | `164[.]90[.]218[.]73` | E7 Sending Server / Hosting IP |
| **IP Address** | `203[.]0[.]113[.]228` | E6 Sending Server / URL Target IP |
| **URL** | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | Phishing Landing Page (E2) |
| **URL** | `hxxps://outlook-protection[.]com/verify` | Phishing Landing Page (E3) |
| **URL** | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | Phishing / Fraud Payment URL (E5) |
| **URL** | `hxxps://meddefense-benefits[.]org/enroll` | Phishing Landing Page (E7) |
| **URL** | `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` | Spam Payload URL (E6) |
| **Sender Email** | `noreply@meddefense-portal[.]com` | Malicious Sender (E2) |
| **Sender Email** | `security@outlook-protection[.]com` | Malicious Sender (E3) |
| **Sender Email** | `invoices@medequip-supplies[.]net` | Malicious Sender (E5) |
| **Sender Email** | `hr-notifications@meddefense-benefits[.]org` | Malicious Sender (E7) |
| **Attachment Hash** | `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f` | SHA-256 of `INV-2026-04891.pdf` (E5) |

## 7. Detection and Control Gaps

### Primary Control Gaps
1. **Permissive DMARC Policy Enforcement:** External messages failing SPF and DMARC (E2, E5, E7) were accepted and delivered to user inboxes due to `action=none` configuration on inbound gateway filters.
2. **Lack of Newly Registered Domain (NRD) Inspection:** Security controls failed to evaluate domain age or reputation for lookalike domains registered less than 30 days prior.
3. **Absence of External Sender Banners:** Inbound external messages successfully impersonated internal departments ("MedDefense IT Security", "MedDefense HR Benefits") without visual indicators distinguishing external origins.

### SIEM & Gateway Detection Rules
* **Rule 1 (Internal Brand Impersonation):** Alert if `Header.From` display name contains internal keywords ("MedDefense", "IT Security") while `Envelope.Sender` domain does not equal `meddefense[.]com`.
* **Rule 2 (PHPMailer Auth Failure):** Block and alert if `X-Mailer` contains `PHPMailer` AND (SPF == FAIL OR DMARC == FAIL) AND email body contains high-urgency keywords ("verify now", "action required", "24 hours").
* **Rule 3 (PDF Hyperlink Inspection):** Hold PDF attachments containing `/Subtype /Link` structures pointing to non-whitelisted external domains for sandbox evaluation.
* **Rule 4 (Newly Registered Lookalike Detection):** Tag and strip links for emails originating from domains registered < 30 days ago matching keyword patterns (`portal`, `benefits`, `supplies`).

## 8. Recommendations

### Immediate Actions (Next 24 Hours)
1. **Account & Endpoint Remediation:** Complete session revocation and password reset for Diane Marsh (`dmarsh@meddefense[.]com`). Perform forensic triage on `WS-NURSE-04`.
2. **Perimeter Blocking:** Ingest all identified IOC domains and IP addresses into perimeter firewalls, DNS resolvers, and Secure Web Gateways (SWG).
3. **Mailbox Purge:** Execute an automated tenant-wide search and purge for all instances of Emails 2, 3, 5, and 7 across all user mailboxes.
4. **Threat Intelligence Sharing:** Submit verified campaign IOCs (`meddefense-portal[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`) to the HC3 portal in response to advisory `HC3-2026-PRELIM-001`.

### Short-Term Actions (Next 7 Days)
1. **Gateway Configuration:** Update email gateway policies to strictly enforce DMARC/SPF compliance, routing failing messages to quarantine.
2. **External Sender Tagging:** Implement mandatory visual warning banners on all incoming external emails (e.g., `[EXTERNAL EMAIL] Do not click links or enter credentials`).
3. **Targeted User Awareness:** Issue a targeted security advisory to Clinical, AP, and Billing departments alerting them to role-tailored credential harvesting and invoice pretexts.

### Medium-Term Actions (Next 30 Days)
1. **DMARC Enforcement:** Shift `meddefense.com` DMARC policy from `p=none` to `p=reject`.
2. **Phishing-Resistant MFA:** Accelerate deployment of FIDO2 / hardware-key phishing-resistant MFA across clinical and administrative staff.
3. **Continuous Domain Monitoring:** Engage a digital risk protection service to automatically detect, alert, and request takedowns for newly registered typosquat and lookalike domains targeting MedDefense brands.
