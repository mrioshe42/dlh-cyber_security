# Email Authentication Analysis

## Email 1 - Healthcare Education Weekly Newsletter

- **SPF:** Pass. The sending IP `198.51.100.42` is explicitly authorized to send mail for `healthcare-education-weekly.com`.
- **DKIM:** Pass. The message contains a valid RSA-SHA256 signature under `header.d=healthcare-education-weekly.com` using selector `mail01`.
- **DMARC:** Pass. DMARC policy is set to `action=none`. The authenticated domain aligns directly with the visible `From:` header domain.
- **Authentication verdict:** Pass (Fully Authenticated).
- **Investigation meaning:** The authentication results support the legitimacy of the sender domain. The email originated from authorized infrastructure used by MailChimp for legitimate third-party newsletter delivery.

## Email 2 - MedDefense Staff Portal Verification Lure

- **SPF:** Fail. Sending IP `91.234.99.107` is not authorized to send mail on behalf of `meddefense-portal.com`.
- **DKIM:** None. The email lacks a DKIM cryptographic signature (`header.d=none`).
- **DMARC:** Fail. DMARC fails with `action=none` because SPF failed and no valid DKIM alignment exists.
- **Authentication verdict:** Fail (Authentication Failure).
- **Investigation meaning:** The email fails all technical authentication checks. The message originated from an unauthorized external IP (`91.234.99.107`) running PHPMailer. This confirms that the sender spoofed the lookalike domain `meddefense-portal.com` in an unauthorized credential harvesting attack directed at Diane Marsh.

## Email 3 — Microsoft Account Protection Notice

- **SPF:** Pass. Sending IP `51.38.42.17` is authorized by the SPF record published for `outlook-protection.com`.
- **DKIM:** Pass. The email includes a valid DKIM signature under `header.d=outlook-protection.com` using selector `default`.
- **DMARC:** Pass. DMARC passes with `action=none` because the `From:` header domain aligns with the authenticated DKIM and SPF domain (`outlook-protection.com`).
- **Authentication verdict:** Pass (Technical Authentication Pass).
- **Investigation meaning:** Technical authentication passes because the adversary registered the lookalike domain `outlook-protection.com` and configured proper SPF, DKIM, and DMARC records for their own sending infrastructure. Passing authentication merely proves that the email originated from the authorized infrastructure of `outlook-protection.com`; it does not prove the domain is trustworthy. Crucially, `outlook-protection.com` is an adversary-controlled typosquatted domain that is completely separate from legitimate Microsoft properties such as `microsoft.com` or `outlook.com`.

## Email 4 - Internal IT Password Change Announcement

- **SPF:** Pass. Sending IP `10.10.1.15` corresponds to internal host `exchange-hub.meddefense.local`, which is authorized for `meddefense.com`.
- **DKIM:** Pass. The email carries a valid DKIM signature signed by `header.d=meddefense.com` using selector `selector1`.
- **DMARC:** Pass. DMARC passes with `action=none`, fully aligning with internal domain `meddefense.com`.
- **Authentication verdict:** Pass (Legitimate Internal Alignment).
- **Investigation meaning:** Authentication confirms that the email originated internally from the organization's Exchange server infrastructure. This verifies the message as a legitimate broadcast notice issued by the internal SOC/IT team.

## Email 5 - MedEquip Supplies Invoice Notice

- **SPF:** Softfail. Sending IP `185.176.43.22` returned a softfail result for `medequip-supplies.net`.
- **DKIM:** None. The message contains no cryptographic DKIM signature (`header.d=none`).
- **DMARC:** Fail. DMARC evaluation failed with `action=none` due to unaligned/failing SPF and missing DKIM signatures.
- **Authentication verdict:** Fail (Authentication Failure).
- **Investigation meaning:** The failure of SPF and DKIM indicates that the sending host is not authorized to deliver mail for `medequip-supplies.net`. The email was generated via PHPMailer from a suspicious hosting IP (`185.176.43.22`), supporting the conclusion that this is an unauthorized fraudulent invoice lure sent to Accounts Payable.

## Email 6 — Canadian Pharma Discounts

- **SPF:** Softfail. Sending IP `203.0.113.228` is not designated as an authorized sender for `canadian-pharma-discount.org`.
- **DKIM:** None. The email is unsigned.
- **DMARC:** Fail. DMARC evaluation failed, triggering `action=quarantine` as dictated by the domain's policy.
- **Authentication verdict:** Fail (Authentication Failure).
- **Investigation meaning:** The email fails domain authentication and was flagged with a Spam Score of 9.8. This confirms the message originated from unauthenticated bulk spam infrastructure.

## Email 7 - MedDefense HR Benefits Open Enrollment Notice

- **SPF:** Fail. Sending IP `164.90.218.73` is not authorized for `meddefense-benefits.org`.
- **DKIM:** None. No DKIM signature is present (`header.d=none`).
- **DMARC:** Fail. DMARC evaluation failed with `action=none`.
- **Authentication verdict:** Fail (Authentication Failure).
- **Investigation meaning:** The email fails all authentication checks and originates from an unauthorized cloud host (`164.90.218.73`) using PHPMailer. The domain `meddefense-benefits.org` is an external lookalike domain created for spear-phishing billing staff (Linda Patterson).

## Email 8 - HC3 Sector Alert Advisory

- **SPF:** Pass. Sending IP `134.174.47.82` is authorized to transmit mail on behalf of `hhs.gov`.
- **DKIM:** Pass. Cryptographically signed and verified by `header.d=hhs.gov` with selector `hhs2026`.
- **DMARC:** Pass. DMARC passes with `action=none`, fully aligning with `hhs.gov`.
- **Authentication verdict:** Pass (Fully Authenticated Official Source).
- **Investigation meaning:** The email is fully authenticated against official government sending infrastructure. This confirms that the alert genuinely originated from the HHS Health Sector Cybersecurity Coordination Center (HC3).
