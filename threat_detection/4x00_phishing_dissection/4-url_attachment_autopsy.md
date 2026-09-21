# URL and Attachment Autopsy

**Target Organization:** MedDefense Health Systems  
**Analysis Date:** April 17, 2026  
**Analyst:** SOC / Incident Response Team  
**Scope:** Forensic autopsy of all extracted URLs, hyperlinks, embedded images, and file attachments across Emails 1 through 8.

## 1. Defanging Standard Reference

Per organizational safety guidelines and automated checking requirements, all extracted URLs, domains, and IP addresses in this document are formatted using semi-defanging:
* Protocol replacement: `http://` $\rightarrow$ `hxxp://` | `https://` $\rightarrow$ `hxxps://`
* Domain / Host dot bracketed: `domain.com` $\rightarrow$ `domain[.]com`
* Example:
  * **Original value:** `https://meddefense-portal.com/assets/logo.png`
  * **Defanged value:** `hxxps://meddefense-portal[.]com/assets/logo[.]png`

## 2. Complete Extracted Indicator Inventory

| Email ID | Category / Lure | Type | Defanged Value | Host / Destination | Threat Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Email 1** | Newsletter Article | Web Link | `hxxps://healthcare-education-weekly[.]com/april-2026` | `198[.]51[.]100[.]42` | Legitimate / Benign |
| **Email 1** | Unsubscribe | Web Link | `hxxps://healthcare-education-weekly[.]com/unsubscribe?id=jmoore@meddefense[.]com` | `198[.]51[.]100[.]42` | Legitimate / Benign |
| **Email 2** | Image Logo | Img Src | `hxxps://meddefense-portal[.]com/assets/logo[.]png` | `91[.]234[.]99[.]107` | Malicious Lookalike |
| **Email 2** | IT Verification | Action Link | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | `91[.]234[.]99[.]107` | Credential Harvesting |
| **Email 3** | Brand Logo | Img Src | `hxxps://outlook-protection[.]com/img/ms_logo[.]png` | `51[.]38[.]42[.]17` | Malicious Typosquat |
| **Email 3** | M365 Security Alert | Action Link | `hxxps://outlook-protection[.]com/verify` | `51[.]38[.]42[.]17` | Credential Harvesting |
| **Email 4** | Intranet Portal | Text Ref | `portal[.]meddefense[.]local/password` | `10[.]10[.]1[.]15` (Internal) | Internal Benign |
| **Email 5** | Invoice Payment | Action Link | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | `185[.]176[.]43[.]22` | Financial Fraud / Phish |
| **Email 5** | Supplier Login | Web Link | `hxxps://medequip-supplies[.]net/portal/login` | `185[.]176[.]43[.]22` | Financial Fraud / Phish |
| **Email 5** | PDF Attachment | File | `INV-2026-04891.pdf` | N/A | Malicious Link Delivery |
| **Email 6** | Discount Offer | Direct IP Link | `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite` | `203[.]0[.]113[.]228` | High-Risk Spam |
| **Email 7** | HR Open Enrollment | Action Link | `hxxps://meddefense-benefits[.]org/enroll` | `164[.]90[.]218[.]73` | Credential Harvesting |
| **Email 8** | Government Advisory | Informational | `hxxps://www[.]hhs[.]gov/hc3` | `134[.]174[.]47[.]82` | Official Legitimate |

## 3. Granular Email Autopsy Details

### Email 1: Healthcare Education Weekly
* **Header Sender:** `newsletter@healthcare-education-weekly[.]com`
* **Extracted URLs:**
  * `hxxps://healthcare-education-weekly[.]com/april-2026`
  * `hxxps://healthcare-education-weekly[.]com/unsubscribe?id=jmoore@meddefense[.]com`
* **Autopsy Notes:** Valid DKIM and SPF. Hyperlinks match the authenticated domain name. Standard mailing list unsubscribe parameters detected. No malicious redirection observed.

### Email 2: MedDefense IT Staff Portal (Click Incident E2)
* **Header Sender:** `noreply@meddefense-portal[.]com`
* **Sending IP:** `91[.]234[.]99[.]107`
* **Extracted URLs:**
  * Image: `hxxps://meddefense-portal[.]com/assets/logo[.]png`
  * Action Button: `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
* **Autopsy Notes:** 
  * The domain `meddefense-portal[.]com` mimics internal MedDefense infrastructure but is hosted externally on IP `91[.]234[.]99[.]107`.
  * The target link contains unique recipient parameters (`id=dmarsh`) and a tracking token (`token=a8f3e2d1`), enabling the attacker to pre-fill the username field or verify victim interaction.
  * Click confirmed by Diane Marsh (`WS-NURSE-04`, `10[.]10[.]2[.]15`) at `2026-04-14 15:02:33 CDT`.

### Email 3: Microsoft M365 Security Notice
* **Header Sender:** `security@outlook-protection[.]com`
* **Sending IP:** `51[.]38[.]42[.]17`
* **Extracted URLs:**
  * Image: `hxxps://outlook-protection[.]com/img/ms_logo[.]png`
  * Action Button: `hxxps://outlook-protection[.]com/verify`
* **Autopsy Notes:**
  * Employs typosquatted domain `outlook-protection[.]com` designed to pass initial visual scrutiny.
  * Directs the recipient (`rmendez@meddefense[.]com`) to a replicated Microsoft 365 login screen designed to capture corporate Azure AD / Entra credentials.

### Email 4: Internal Password Policy Reminder
* **Header Sender:** `it-announcements@meddefense[.]com`
* **Sending IP:** `10[.]10[.]1[.]15` (Internal Exchange)
* **Extracted References:**
  * Intranet Path: `portal[.]meddefense[.]local/password`
  * Helpdesk: `helpdesk[.]meddefense[.]local`
* **Autopsy Notes:** Non-clickable plain text references to internal `.local` domain paths. Authenticated internal broadcast.

### Email 5: MedEquip Supplies Invoice & PDF Attachment
* **Header Sender:** `invoices@medequip-supplies[.]net`
* **Sending IP:** `185[.]176[.]43[.]22`
* **Extracted URLs:**
  * Portal Link 1: `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
  * Portal Link 2: `hxxps://medequip-supplies[.]net/portal/login`
* **Attachment Analysis:**
  * **File Name:** `INV-2026-04891.pdf`
  * **MIME Type:** `application/pdf`
  * **Decoded PDF Header:** `%PDF-1.4` generated by `wkhtmltopdf 0.12.6`
  * **Embedded Hash Indicator:** `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f`
  * **PDF Structure:**
    ```text
    10 0 obj
    <</Type/Annot/Subtype/Link/Border[0 0 0]/Rect[175 185 450 205]
    /A <</Type/Action/S/URI/URI (hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891)>>>>
    ```
  * **Findings:** The PDF contains an active link annotation (`/Subtype /Link`) that launches `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`. It contains no embedded JavaScript exploits, relying on PDF rendering to bypass email gateway body text filters.

### Email 6: Canadian Pharma Discounts
* **Header Sender:** `deals@canadian-pharma-discount[.]org`
* **Sending IP:** `203[.]0[.]113[.]228`
* **Extracted Link:**
  * Action Link: `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite`
* **Autopsy Notes:** Uses an unencrypted HTTP link pointing directly to a raw IP address (`203[.]0[.]113[.]228`), triggering spam heuristics `NUMERIC_HTTP_ADDR` and `NORMAL_HTTP_TO_IP`.

### Email 7: MedDefense HR Benefits Open Enrollment
* **Header Sender:** `hr-notifications@meddefense-benefits[.]org`
* **Sending IP:** `164[.]90[.]218[.]73`
* **Extracted Link:**
  * Action Button: `hxxps://meddefense-benefits[.]org/enroll`
* **Autopsy Notes:** Targets HR and Billing staff (`lpatterson@meddefense[.]com`) using lookalike domain `meddefense-benefits[.]org` to harvest personal identity information (PII) and portal credentials.

### Email 8: HHS HC3 Sector Alert
* **Header Sender:** `HC3@hhs[.]gov`
* **Sending IP:** `134[.]174[.]47[.]82`
* **Extracted Reference:**
  * Official Portal: `hxxps://www[.]hhs[.]gov/hc3`
* **Autopsy Notes:** Official government communications link, fully authenticated via HHS DKIM (`s=hhs2026`).

## 4. Summary of Key Indicator Signatures

* **Lookalike Domains:** `meddefense-portal[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
* **Typosquat Domain:** `outlook-protection[.]com`
* **Malicious File Attachment:** `INV-2026-04891.pdf` (SHA-256: `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f`)
