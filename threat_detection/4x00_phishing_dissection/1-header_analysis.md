# Email Evidence Batch Header Analysis

## Email 2 - meddefense-portal.com

### Header Evidence
- **From:** `"MedDefense IT Security" <noreply@meddefense-portal.com>`
- **Return-Path:** `<noreply@meddefense-portal.com>`
- **Sending IP:** `91.234.99.107`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-5D7E2F4A@meddefense-portal.com>`

### Received Chain Summary
1. **Internal Origin / Script:** `localhost [127.0.0.1]` to `mail.meddefense-portal.com` with PHPMailer 6.6.0 (ID: `PHP-5D7E2F4A`) on `Mon, 14 Apr 2026 19:47:48 +0000`.
2. **External Gateway to Inbound Gateway:** `mail.meddefense-portal.com ([91.234.99.107])` to `mx01.meddefense.com` via ESMTP (ID: `6E4A1B23`) on `Mon, 14 Apr 2026 14:47:51 -0500`.
3. **Inbound Gateway to Internal Relay:** `mx01.meddefense.com ([10.10.1.20])` to `inbound-relay.meddefense.com` via ESMTP (ID: `7F8D3C9B`) on `Mon, 14 Apr 2026 14:47:52 -0500`.

### Anomalies
- **[HIGH] Domain Spoofing / Impersonation:** The domain `meddefense-portal.com` mimics the legitimate organization domain (`meddefense.com`), claiming to originate from internal "MedDefense IT Security".
- **[HIGH] Authentication Failures:** SPF check failed (`spf=fail (sender IP 91.234.99.107 not authorized for meddefense-portal.com)`) and DMARC failed (`dmarc=fail`). No DKIM signature was present (`dkim=none`).
- **[MEDIUM] Suspicious Mailer Infrastructure:** The email was generated via web-script (`PHPMailer 6.6.0`) hosted on external IP `91.234.99.107` rather than official Exchange or M365 infrastructure.

### Conclusion
Email 2 is a malicious credential-harvesting phishing attack using lookalike domain spoofing (`meddefense-portal.com`). The email failed SPF and DMARC verification and was dispatched via generic PHPMailer infrastructure.

## Email 3 - outlook-protection.com

### Header Evidence
- **From:** `"Microsoft Account Protection" <security@outlook-protection.com>`
- **Return-Path:** `<security@outlook-protection.com>`
- **Sending IP:** `51.38.42.17`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-9F2D7E1B@outlook-protection.com>`

### Received Chain Summary
1. **Internal Origin / Script:** `wp-admin.outlook-protection.com (localhost [127.0.0.1])` to `mail.outlook-protection.com` with PHPMailer 6.6.0 (ID: `PHP-9F2D7E1B`) on `Tue, 15 Apr 2026 14:13:40 +0000`.
2. **External Gateway to Inbound Gateway:** `mail.outlook-protection.com ([51.38.42.17])` to `mx01.meddefense.com` via ESMTPS (ID: `5D7A2B1C`) on `Tue, 15 Apr 2026 09:13:43 -0500`.
3. **Inbound Gateway to Internal Relay:** `mx01.meddefense.com ([10.10.1.20])` to `inbound-relay.meddefense.com` via ESMTP (ID: `8A2B4E7C`) on `Tue, 15 Apr 2026 09:13:44 -0500`.

### Anomalies
- **[HIGH] Brand Impersonation:** Uses lookalike domain `outlook-protection.com` to impersonate Microsoft Account Protection services. Official Microsoft notifications do not originate from this domain.
- **[HIGH] Fraudulent DKIM Signature Value:** While `Authentication-Results` indicates a pass for the attacker's domain `outlook-protection.com`, the DKIM `b=` signature string contains hardcoded plaintext (`TrustMeIHaveAValidSignatureFromOutlookProtectionDotCom...`), indicating custom/crafted sending infrastructure.
- **[MEDIUM] Web CMS Mail Generation:** The first `Received` hop lists `wp-admin.outlook-protection.com`, demonstrating the mail was sent from a WordPress backend using `PHPMailer 6.6.0` on VPS hosting.

### Conclusion
Email 3 is an external phishing campaign targeting Microsoft 365 credentials by spoofing Microsoft security notifications through a attacker-controlled domain (`outlook-protection.com`).

## Email 5 - medequip-supplies.net

### Header Evidence
- **From:** `"MedEquip Supplies Billing" <invoices@medequip-supplies.net>`
- **Return-Path:** `<invoices@medequip-supplies.net>`
- **Sending IP:** `185.176.43.22`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-7C2D4E1A@medequip-supplies.net>`

### Received Chain Summary
1. **Internal Origin / Script:** `billing-svc.medequip-supplies.net (localhost [127.0.0.1])` to `mail.medequip-supplies.net` with PHPMailer 6.6.0 (ID: `PHP-7C2D4E1A`) on `Wed, 16 Apr 2026 16:28:35 +0000`.
2. **External Gateway to Inbound Gateway:** `mail.medequip-supplies.net ([185.176.43.22])` to `mx01.meddefense.com` via ESMTP (ID: `1E4F2B8D`) on `Wed, 16 Apr 2026 11:28:37 -0500`.
3. **Inbound Gateway to Internal Relay:** `mx01.meddefense.com ([10.10.1.20])` to `inbound-relay.meddefense.com` via ESMTP (ID: `6B3E7A2C`) on `Wed, 16 Apr 2026 11:28:39 -0500`.

### Anomalies
- **[HIGH] Authentication Failure:** SPF evaluation resulted in `softfail` (`sender IP 185.176.43.22 is softfail for medequip-supplies.net`), leading to DMARC failure (`dmarc=fail`).
- **[HIGH] Fraudulent Invoice / Vendor Phishing:** Targeted toward Accounts Payable (`arivera@meddefense.com`) using a lookalike vendor domain (`medequip-supplies.net`) accompanied by a fake PDF attachment (`INV-2026-04891.pdf`) containing embedded URI links.
- **[MEDIUM] Mailer & Signature Anomalies:** Lacks DKIM signing (`dkim=none`) and uses PHPMailer 6.6.0 on a foreign IP address (`185.176.43.22`).

### Conclusion
Email 5 is a Business Email Compromise (BEC) / Invoice Fraud attempt attempting to lure AP staff to a fake payment portal via a spoofed vendor domain.

## Email 7 - meddefense-benefits.org

### Header Evidence
- **From:** `"MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>`
- **Return-Path:** `<hr-notifications@meddefense-benefits.org>`
- **Sending IP:** `164.90.218.73`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-2E4A7B1C@meddefense-benefits.org>`

### Received Chain Summary
1. **Internal Origin / Script:** `wp-portal.meddefense-benefits.org (localhost [127.0.0.1])` to `mail.meddefense-benefits.org` with PHPMailer 6.6.0 (ID: `PHP-2E4A7B1C`) on `Thu, 16 Apr 2026 20:22:02 +0000`.
2. **External Gateway to Inbound Gateway:** `mail.meddefense-benefits.org ([164.90.218.73])` to `mx01.meddefense.com` via ESMTP (ID: `7D2F4B9A`) on `Thu, 16 Apr 2026 15:22:05 -0500`.
3. **Inbound Gateway to Internal Relay:** `mx01.meddefense.com ([10.10.1.20])` to `inbound-relay.meddefense.com` via ESMTP (ID: `3C8E4A7B`) on `Thu, 16 Apr 2026 15:22:07 -0500`.

### Anomalies
- **[HIGH] Spoofed HR Domain:** Uses lookalike domain `meddefense-benefits.org` to impersonate internal MedDefense Human Resources Open Enrollment.
- **[HIGH] Authentication Failures:** Fails SPF validation (`spf=fail (sender IP 164.90.218.73 not authorized for meddefense-benefits.org)`) and DMARC (`dmarc=fail`). Unsigned email (`dkim=none`).
- **[MEDIUM] Shared Threat Infrastructure:** Uses the exact same user-agent string (`PHPMailer 6.6.0`) originating from a WordPress application instance (`wp-portal.meddefense-benefits.org`) hosted on DigitalOcean/VPS infrastructure (`164.90.218.73`), matching patterns outlined in HC3 Alert E8.

### Conclusion
Email 7 is a targeted credential harvesting attack against HR/Billing personnel using a spoofed benefit enrollment pretext and lookalike domain (`meddefense-benefits.org`).
