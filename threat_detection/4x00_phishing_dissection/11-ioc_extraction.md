# The IOC Extraction

**Document ID:** IOC-2026-MDH-001  
**Target Organization:** MedDefense Health Systems  
**Date of Extraction:** April 17, 2026  
**Analyst / SOC Reference:** Incident Response Team / Ref: INC-2026-04-14-7741  
**TLP Classification:** TLP:AMBER (Internal distribution and trusted healthcare security partners)

## 1. Executive Summary

This document extracts, categorizes, and evaluates Indicators of Compromise (IOCs) identified during the investigation of a coordinated phishing and credential harvesting campaign targeting MedDefense Health Systems between April 14 and April 16, 2026. 

The campaign utilized role-targeted social engineering lures across clinical, accounts payable, and administrative staff. Malicious actors deployed newly registered lookalike domains (`.com`, `.net`, `.org`), unauthenticated PHPMailer instances hosted on budget Cloud/VPS providers, and weaponized PDF attachments containing embedded redirection links.

## 2. Master Structured IOC Table

| IOC Type | Defanged Value | Source | Context / Description | Confidence | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Domain** | `meddefense-portal[.]com` | Email 2 | Impersonates MedDefense staff portal; used for nurse credential harvesting lure. | **HIGH** | Block at DNS/Firewall/Proxy |
| **Domain** | `outlook-protection[.]com` | Email 3 | Impersonates Microsoft 365 security notification; targets clinical/administrative staff. | **HIGH** | Block at DNS/Firewall/Proxy |
| **Domain** | `medequip-supplies[.]net` | Email 5 | Typosquatting/lookalike domain for vendor MedEquip Supplies; used in AP invoice fraud lure. | **HIGH** | Block at DNS/Firewall/Proxy |
| **Domain** | `meddefense-benefits[.]org` | Email 7 | Impersonates MedDefense HR Benefits department; open enrollment urgency lure. | **HIGH** | Block at DNS/Firewall/Proxy |
| **IP Address** | `91.234.99[.]107` | Email 2 | Originating MTA IP for `mail.meddefense-portal[.]com`; hosted on budget offshore VPS. | **HIGH** | Block inbound at Perimeter Firewall / Gateway |
| **IP Address** | `51.38.42[.]17` | Email 3 | Originating MTA IP for `mail.outlook-protection[.]com` (OVH / European hosting). | **HIGH** | Block inbound at Perimeter Firewall / Gateway |
| **IP Address** | `185.176.43[.]22` | Email 5 | Originating MTA IP for `mail.medequip-supplies[.]net`. | **HIGH** | Block inbound at Perimeter Firewall / Gateway |
| **IP Address** | `164.90.218[.]73` | Email 7 | Originating MTA IP for `mail.meddefense-benefits[.]org` (DigitalOcean infrastructure). | **HIGH** | Block inbound at Perimeter Firewall / Gateway |
| **IP Address** | `41.203.72[.]188` | Email 3 | Fake sign-in location IP cited inside body of Email 3 (Lagos, Nigeria). | **LOW** | Context / Monitor only (Do NOT block as threat actor) |
| **Email Address** | `noreply[at]meddefense-portal[.]com` | Email 2 | Sender address for portal re-verification phishing lure. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `no-reply[at]meddefense-portal[.]com` | Email 2 | Reply-To header address for portal re-verification phishing lure. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `security[at]outlook-protection[.]com` | Email 3 | Sender address for fake Microsoft 365 security alert. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `no-reply[at]outlook-protection[.]com` | Email 3 | Reply-To address for fake Microsoft 365 security alert. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `invoices[at]medequip-supplies[.]net` | Email 5 | Sender address for fraudulent AP invoice lure. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `billing[at]medequip-supplies[.]net` | Email 5 | Reply-To address for fraudulent AP invoice lure. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `hr-notifications[at]meddefense-benefits[.]org` | Email 7 | Sender address for fake HR Open Enrollment lure. | **HIGH** | Block sender at Email Gateway |
| **Email Address** | `no-reply[at]meddefense-benefits[.]org` | Email 7 | Reply-To address for fake HR Open Enrollment lure. | **HIGH** | Block sender at Email Gateway |
| **URL** | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | Email 2 | Credential harvesting landing page targeting Diane Marsh (`dmarsh`). | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://meddefense-portal[.]com/assets/logo.png` | Email 2 | Image asset URL used for brand impersonation in email body. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://outlook-protection[.]com/verify` | Email 3 | Credential harvesting landing page targeting M365 users. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://outlook-protection[.]com/img/ms_logo.png` | Email 3 | Image asset URL used for Microsoft branding impersonation. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | Email 5 | Fraudulent payment portal / credential harvesting page. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://medequip-supplies[.]net/portal/login` | Email 5 | Direct login credential harvesting link in email body. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | Email 5 (PDF Annot) | Embedded URI Action object link inside `INV-2026-04891.pdf`. | **HIGH** | Block URL on Proxy/Web Filter |
| **URL** | `hxxps://meddefense-benefits[.]org/enroll` | Email 7 | Credential harvesting landing page for HR open enrollment lure. | **HIGH** | Block URL on Proxy/Web Filter |
| **File Hash (SHA-256)** | `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f3q7ce901f` | Email 5 Attachment | SHA-256 hash of malicious PDF attachment `INV-2026-04891.pdf`. | **HIGH** | Block / Quarantine File Hash in EDR/AV |
| **Tool / Software** | `PHPMailer 6.6.0` | Emails 2, 3, 5, 7 | Sending software identified in `X-Mailer` and `Received` headers across campaign. | **LOW** | Context / Monitor only |
| **Tool / Software** | `wkhtmltopdf 0.12.6` | Email 5 (PDF Meta) | Document generation library metadata (`Producer`) in PDF attachment. | **LOW** | Context / Detection rule tuning |
| **Infrastructure Note** | `wp-admin.outlook-protection[.]com` | Email 3 Header | Internal hostname in `Received` header indicating WordPress backend staging. | **MEDIUM** | Hunt for related staging hostnames |
| **Infrastructure Note** | `wp-portal.meddefense-benefits[.]org` | Email 7 Header | Internal hostname in `Received` header indicating WordPress backend staging. | **MEDIUM** | Hunt for related staging hostnames |

## 3. Categorization by Attack Phase

### Phase 1: Delivery
*   **Sender Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
*   **Sender Addresses:** `noreply[at]meddefense-portal[.]com`, `security[at]outlook-protection[.]com`, `invoices[at]medequip-supplies[.]net`, `hr-notifications[at]meddefense-benefits[.]org`
*   **Originating IP Addresses:** `91.234.99[.]107`, `51.38.42[.]17`, `185.176.43[.]22`, `164.90.218[.]73`
*   **Authentication Violations:** SPF failures/softfails and missing DKIM signatures on emails 2, 5, and 7.

### Phase 2: Credential Harvesting & Staging
*   **Primary Landing URLs:**
    *   `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
    *   `hxxps://outlook-protection[.]com/verify`
    *   `hxxps://medequip-supplies[.]net/portal/login`
    *   `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
    *   `hxxps://meddefense-benefits[.]org/enroll`
*   **Hosted Image Assets:** Logo graphics hosted directly on phishing infrastructure (`/assets/logo.png`, `/img/ms_logo.png`) to evade external image proxy blocking.

### Phase 3: Attachment & Lure Artifacts
*   **Attachment File Name:** `INV-2026-04891.pdf`
*   **Attachment Hash (SHA-256):** `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f3q7ce901f`
*   **Embedded PDF Action Object:** Link annotation `/Subtype /Link /A << /Type /Action /S /URI /URI (https://medequip-supplies.net/invoices/pay?id=INV-2026-04891) >>`
*   **PDF Generation Metadata:** Producer string `wkhtmltopdf 0.12.6` converting HTML template to PDF invoice.

### Phase 4: Infrastructure & Staging
*   **Server Staging Hostnames:**
    *   `wp-admin.outlook-protection[.]com` (localhost [127.0.0.1])
    *   `wp-portal.meddefense-benefits[.]org` (localhost [127.0.0.1])
    *   `billing-svc.medequip-supplies.net` (localhost [127.0.0.1])
*   **Mailer Framework:** PHPMailer v6.6.0 on Linux/Apache hosting.
*   **VPS / Hosting Providers:** DigitalOcean (`164.90.218[.]73`), OVH (`51.38.42[.]17`), Offshore budget VPS (`91.234.99[.]107`, `185.176.43[.]22`).

### Phase 5: Context-Only Indicators
*   **Bogus IP inside Message Body:** `41.203.72[.]188` (referenced in Email 3 as a fake sign-in attempt from Lagos, Nigeria to induce panic).
*   **Internal Legitimate IP Baseline (Reference):** `10.10.1.20` (Inbound MX `mx01.meddefense.com`), `10.10.1.15` (`exchange-hub.meddefense.local`).

## 4. IOC Quality & Actionability Analysis

### A. High-Confidence IOCs (Safe to Block Immediately)
*   **Lookalike Phishing Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`.
    *   *Justification:* These domains are explicitly designed to impersonate internal systems and key vendors. They have no legitimate operational purpose for MedDefense personnel.
*   **Campaign Specific URLs:** Exact verification and payment URLs.
    *   *Justification:* Directly linked to harvesting forms and active token tracking.
*   **PDF Attachment SHA-256 Hash:** `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f3q7ce901f`.
    *   *Justification:* Cryptographic file hash uniquely identifying the weaponized PDF invoice.

### B. Medium-Confidence IOCs (Monitor / Require Egress Correlation)
*   **Sending Server IP Addresses (`91.234.99[.]107`, `51.38.42[.]17`, `185.176.43[.]22`, `164.90.218[.]73`):**
    *   *Justification:* While these IPs actively routed attack traffic during this campaign, budget VPS IP space (e.g., DigitalOcean, OVH) is routinely reassigned. Inbound blocking on email gateways is recommended immediately, but firewall blocks should be re-evaluated periodically (30–90 days).

### C. Low-Confidence / Context-Only Indicators (Do NOT Block Standalone)
1.  **Text Body IP (`41.203.72[.]188`):**
    *   *Risk if blocked:* This IP was typed into the HTML body by the attacker as social engineering pretext ("Unusual sign-in attempt"). It may belong to an innocent residential ISP or web crawler in Nigeria. Blocking it at the firewall provides no defense and wastes rule table space.
2.  **X-Mailer String (`PHPMailer 6.6.0`):**
    *   *Risk if blocked:* PHPMailer is one of the most widely used legitimate PHP mailing libraries globally. Blocking all emails with this header will cause significant false positives for legitimate web form submissions, newsletters, and third-party automated alerts.
3.  **PDF Producer (`wkhtmltopdf 0.12.6`):**
    *   *Risk if blocked:* `wkhtmltopdf` is an open-source tool used by legitimate businesses to generate PDF receipts and reports from HTML templates.
4.  **Domain Naming Patterns (`portal`, `benefits`, `supplies`):**
    *   *Risk if blocked:* Generic keywords cannot be string-blocked globally without breaking legitimate external service integrations. Keyword rules should only be used in combination with domain age (<30 days) or authentication failures.

## 5. HC3-Ready Campaign Intelligence Summary

The summary below is formatted for immediate submission to the **Health Sector Cybersecurity Coordination Center (HC3)** and regional H-ISAC threat sharing channels.

```yaml

ALERT_REFERENCE: HC3-2026-PRELIM-001 Submittal
TLP: CLEAR
TARGETED_SECTOR: Healthcare & Public Health (HPH) - Regional Hospitals / Health Systems
CAMPAIGN_TYPE: Targeted Credential Harvesting & Business Email Compromise (BEC)
ATTACK_VECTOR: Role-Tailored Email Phishing with Weaponized Lookalike Domains

OBSERVED_DOMAINS:
  - meddefense-portal[.]com        
  - outlook-protection[.]com      
  - medequip-supplies[.]net     
  - meddefense-benefits[.]org  

OBSERVED_SENDING_IPS:
  - 91.234.99[.]107                
  - 51.38.42[.]17             
  - 185.176.43[.]22               
  - 164.90.218[.]73             

MALICIOUS_SENDER_ADDRESSES:
  - noreply[at]meddefense-portal[.]com
  - security[at]outlook-protection[.]com
  - invoices[at]medequip-supplies[.]net
  - hr-notifications[at]meddefense-benefits[.]org

KEY_URLS_FOR_BLOCKING:
  - hxxps://meddefense-portal[.]com/verify/staff
  - hxxps://outlook-protection[.]com/verify
  - hxxps://medequip-supplies[.]net/invoices/pay
  - hxxps://medequip-supplies[.]net/portal/login
  - hxxps://meddefense-benefits[.]org/enroll

ATTACHMENT_INDICATORS:
  - File Name: INV-2026-04891.pdf
  - File Type: PDF (wkhtmltopdf 0.12.6 generated)
  - SHA-256: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f3q7ce901f
  - Payload Mechanism: PDF URI Annotation redirecting to credential harvesting URL

CAMPAIGN_BEHAVIORAL_NOTES:
  1. Emails leverage newly registered domains (<30 days old) mimicking employer brand and trusted vendors.
  2. Pervasive use of unauthenticated PHPMailer script installations hosted on WordPress sites or standalone VPS containers.
  3. Pretexts exploit tight artificial deadlines (24-48 hour lockouts, 7-day payment demands, open enrollment cutoffs).

```
