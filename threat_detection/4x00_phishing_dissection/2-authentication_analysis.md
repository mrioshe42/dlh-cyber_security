# Email Authentication Analysis

## Email 1 - healthcare-education-weekly.com

- **SPF:** Pass - Sending IP `198.51.100.42` is explicitly authorized to send mail on behalf of `healthcare-education-weekly.com`.
- **DKIM:** Pass - The message contains a valid cryptographic signature aligned with domain `healthcare-education-weekly.com`.
- **DMARC:** Pass - DMARC evaluation indicates `p=none` (`action=none`), with strict alignment between the visible `From:` domain and authenticated domains.
- **Authentication verdict:** Pass - Technical authentication is fully aligned with the sending domain.
- **Investigation meaning:** Passing SPF, DKIM, and DMARC confirms that the sending infrastructure is authorized by `healthcare-education-weekly.com`. This supports sender domain alignment, increases confidence in sender identity, and indicates that the message originated from legitimate sending infrastructure associated with the domain.

## Email 2 - meddefense-portal.com

- **SPF:** Fail - Sending IP `91.234.99.107` is not authorized to send mail for `meddefense-portal.com`.
- **DKIM:** None - No DKIM cryptographic signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed with `action=none` due to failing SPF and missing DKIM signatures.
- **Authentication verdict:** Fail - High Suspicion / Unauthorized Sender.
- **Investigation meaning:** Complete authentication failure across SPF and DMARC indicates that the sending host (`91.234.99.107`) is not authorized to transmit emails for `meddefense-portal.com`. In an investigation, these failed authentication results directly reduce sender trust, strongly support suspicion of domain spoofing and unauthorized impersonation, and justify classifying the message as untrusted.

## Email 3 - outlook-protection.com

- **SPF:** Pass - Sending IP `51.38.42.17` is authorized by the SPF record published for `outlook-protection.com`.
- **DKIM:** Pass - The message contains a valid DKIM signature matching domain `outlook-protection.com`.
- **DMARC:** Pass - DMARC passes with `action=none` because the `From:` header domain aligns with the authenticated domain `outlook-protection.com`.
- **Authentication verdict:** Pass - Technical Authentication Pass on Adversary Infrastructure.
- **Investigation meaning:** Passing SPF, DKIM, and DMARC demonstrates that the email originated from infrastructure authorized for `outlook-protection.com`. However, passing technical authentication does not make the email legitimate or trustworthy. Passing authentication merely proves that the email came from servers authorized by the owner of `outlook-protection.com`; it does not prove legitimate brand authorization, as `outlook-protection.com` is an adversary-controlled lookalike domain and is not the same as `microsoft.com` or `outlook.com`. Consequently, despite passing authentication, the message remains highly suspicious due to brand impersonation.

## Email 4 - meddefense.com

- **SPF:** Pass - Sending IP `10.10.1.15` is authorized to deliver mail on behalf of `meddefense.com`.
- **DKIM:** Pass - The message contains a valid DKIM signature aligned with domain `meddefense.com`.
- **DMARC:** Pass - DMARC evaluation indicates `action=none`, fully aligning with domain `meddefense.com`.
- **Authentication verdict:** Pass - Verified Internal Alignment.
- **Investigation meaning:** All technical authentication checks pass and align with the organizational domain `meddefense.com`. This supports technical domain alignment and indicates that the message originated from authorized internal email infrastructure.

## Email 5 - medequip-supplies.net

- **SPF:** Softfail - Sending IP `185.176.43.22` is not explicitly authorized to send mail for `medequip-supplies.net` (`softfail`).
- **DKIM:** None - No cryptographic DKIM signature is present in the message headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed with `action=none` due to unaligned SPF and absent DKIM signature.
- **Authentication verdict:** Fail - Reduced Trust / Weak Authentication.
- **Investigation meaning:** An SPF softfail combined with missing DKIM signing demonstrates that the sending IP `185.176.43.22` lacks proper sending authorization for `medequip-supplies.net`. These weak and failing authentication indicators directly lower trust in the sender, raise strong suspicion of unauthorized vendor impersonation, and warrant treating the message as untrusted during analysis.

## Email 6 - canadian-pharma-discount.org

- **SPF:** Softfail - Sending IP `203.0.113.228` is not designated as an authorized sender for `canadian-pharma-discount.org`.
- **DKIM:** None - No DKIM signature is present (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed, triggering `action=quarantine` under the domain's published policy.
- **Authentication verdict:** Fail - Reduced Trust / High Spam Suspicion.
- **Investigation meaning:** DMARC failure and SPF softfail indicate that the message originated from an unauthenticated external source outside the domain's authorized infrastructure. This failed authentication directly reduces sender trust, strongly supports suspicion of unauthenticated bulk spam or malicious delivery, and explains why mail gateway enforcement quarantined the message.

## Email 7 - meddefense-benefits.org

- **SPF:** Fail - Sending IP `164.90.218.73` is not authorized to send mail for `meddefense-benefits.org`.
- **DKIM:** None - No DKIM signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed with `action=none` due to failed SPF and missing DKIM signature.
- **Authentication verdict:** Fail - High Suspicion / Unauthorized Sender.
- **Investigation meaning:** Total failure of SPF and DMARC confirms that the sending host `164.90.218.73` is not authorized to send emails for `meddefense-benefits.org`. In an investigative context, these authentication failures significantly lower message trust, strongly support suspicion of unauthorized domain spoofing and HR impersonation, and indicate that the email should be treated as untrusted.

## Email 8 - hhs.gov

- **SPF:** Pass - Sending IP `134.174.47.82` is authorized to transmit mail for `hhs.gov`.
- **DKIM:** Pass - The message contains a valid signature aligned with domain `hhs.gov`.
- **DMARC:** Pass - DMARC evaluation indicates `action=none`, showing full domain alignment with `hhs.gov`.
- **Authentication verdict:** Pass - Verified Official Source.
- **Investigation meaning:** Passing SPF, DKIM, and DMARC confirms that the message was transmitted by infrastructure authorized for `hhs.gov`. This supports technical confidence in the email's origin and indicates legitimate domain authorization.
