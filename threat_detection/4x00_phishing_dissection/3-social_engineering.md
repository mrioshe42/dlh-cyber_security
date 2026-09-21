# Social Engineering Analysis

## Email 2 - MedDefense Staff Portal Verification Lure

* **Psychological lever:** Urgency, Fear, and Impersonation (Authority)
* **Pretext:** A mandatory staff portal re-verification is required following a weekend security policy update, threatening access suspension within 24 hours if not completed immediately.
* **Requested action:** Click the embedded action link (`https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`) and input login credentials to re-verify staff portal access.
* **Targeting level:** TARGETED
* **Content red flags:**
  * Severe artificial deadline (24 hours) threatening direct disruption to daily clinical workflows.
  * Inflated email priority flags (`X-Priority: 1 (Highest)`, `Importance: High`).
  * External lookalike domain (`meddefense-portal.com`) constructed to mimic official corporate infrastructure (`meddefense.com`).
  * Manufactured administrative ticket identifier (`INC-2026-04-14-7741`) intended to bypass scrutiny.
  * Sent via generic PHPMailer script on an unauthorized external host (`91.234.99.107`).
* **Attacker knowledge required:**
  * Target's full name (Diane Marsh) and direct email address (`dmarsh@meddefense.com`).
  * Target's specific operational role as nursing/clinical staff (`WS-NURSE-04`).
  * Specific internal systems and daily healthcare tools used by clinical staff ("scheduling system", "EHR gateway", "shift swap requests").
* **Conclusion:** This is a highly focused spear-phishing attack (credential harvesting) tailored specifically to clinical staff. By threatening access loss to critical patient scheduling and EHR systems, the adversary induced operational panic, resulting in the verified user click by Diane Marsh.

## Email 3 - Microsoft Account Protection Notice

* **Psychological lever:** Fear and Urgency
* **Pretext:** An automated security alert from Microsoft reporting an unauthorized sign-in attempt from Lagos, Nigeria, warning that the account will be locked within 48 hours unless verified.
* **Requested action:** Click the "Verify account" link (`https://outlook-protection.com/verify`) and authenticate with M365 corporate credentials.
* **Targeting level:** SEMI-TARGETED
* **Content red flags:**
  * Typosquatted domain (`outlook-protection.com`) designed to mimic genuine Microsoft notification domains.
  * Geolocation shock tactic detailing specific foreign location (Lagos, Nigeria) and IP address (`41.203.72.188`) to prompt knee-jerk panic.
  * Explicit account lockout threat within 48 hours.
  * Header analysis reveals sending origin via PHPMailer script on a cloud VPS (`51.38.42.17`) rather than Microsoft's native sending infrastructure.
* **Attacker knowledge required:**
  * Target's name (Rafael Mendez) and corporate email address (`rmendez@meddefense.com`).
  * Knowledge that MedDefense relies on Microsoft 365 / Outlook for corporate identity and mail services.
* **Conclusion:** A semi-targeted credential harvesting campaign using standard Microsoft M365 security alert branding. Although built on a reusable template, the inclusion of personalized recipient details and high-contrast threat messaging creates strong psychological leverage.

## Email 5 - MedEquip Supplies Invoice Notice

* **Psychological lever:** Financial Pressure, Urgency, and Impersonation
* **Pretext:** An urgent outstanding invoice notice (INV-2026-04891) for medical supplies delivered on April 9, 2026, demanding payment of USD $24,716.38 within 7 days to avoid late fees and delivery suspension.
* **Requested action:** Click the embedded payment URL (`https://medequip-supplies.net/invoices/pay...`), access the portal login page, or open the attached PDF document (`INV-2026-04891.pdf`).
* **Targeting level:** TARGETED
* **Content red flags:**
  * Generic salutation ("Dear Accounts Payable") despite being routed directly to a specific AP staff member (Angela Rivera).
  * Unusually tight payment terms (7 days) accompanied by threats of a 2% late fee and supply chain suspension.
  * Sender domain mismatch (`medequip-supplies.net`) coupled with SPF softfail and missing DKIM signature.
  * Embedded PDF attachment (`INV-2026-04891.pdf`) containing active URI action annotations designed to redirect users to external payment harvesting portals.
* **Attacker knowledge required:**
  * Identity, role, and email address of Accounts Payable personnel (Angela Rivera).
  * Standard healthcare vendor naming conventions ("MedEquip Supplies") and realistic medical supply procurement amounts.
  * Corporate accounts payable approval workflows and payment scheduling cycles.
* **Conclusion:** A targeted Business Email Compromise (BEC) and invoice fraud lure designed to bypass standard procurement verification by triggering urgency regarding vendor delivery holds and late fees.

## Email 7 - MedDefense HR Benefits Open Enrollment Notice

* **Psychological lever:** Fear of Loss and Urgency
* **Pretext:** A final HR notice informing the recipient that 2026 Open Enrollment closes at midnight tomorrow, warning that failure to complete re-enrollment will result in immediate benefit coverage lapse and default to a basic plan.
* **Requested action:** Click the "COMPLETE ENROLLMENT" button (`https://meddefense-benefits.org/enroll`) and enter personal/SSO authentication credentials.
* **Targeting level:** TARGETED
* **Content red flags:**
  * External lookalike domain (`meddefense-benefits.org`) impersonating internal Human Resources administration.
  * High-stakes penalty threat (loss of active health insurance coverage) paired with a 24-hour deadline.
  * Sent via PHP script hosted on an unauthorized cloud provider (`164.90.218.73`).
  * Fails basic authentication protocols (SPF fail, DKIM missing, DMARC fail).
* **Attacker knowledge required:**
  * Target's full name (Linda Patterson) and organizational email address.
  * Corporate HR benefit terminology ("Open Enrollment", "coverage lapse", "defaulted to a basic plan").
  * Seasonal organizational benefit cycles.
* **Conclusion:** A sophisticated spear-phishing lure exploiting personal anxiety surrounding health insurance coverage. By fabricating a impending cutoff date, the attacker aims to capture single sign-on credentials or personal identity data.
