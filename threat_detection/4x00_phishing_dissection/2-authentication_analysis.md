# Email Authentication Analysis

## Email 1 - healthcare-education-weekly.com

- **SPF:** Pass - Sending IP `198.51.100.42` is authorized to send mail on behalf of `healthcare-education-weekly.com`.
- **DKIM:** Pass - The message contains a valid signature aligned with domain `healthcare-education-weekly.com`.
- **DMARC:** Pass - DMARC evaluation indicates `p=none` (`action=none`), with alignment between the `From:` header domain and authenticated domains.
- **Authentication verdict:** Pass - Technical authentication is aligned with the sending domain.
- **Investigation meaning:** Authentication results indicate that the email was transmitted by infrastructure authorized by `healthcare-education-weekly.com`, supporting technical domain alignment for this sender.

## Email 2 - meddefense-portal.com

- **SPF:** Fail - Sending IP `91.234.99.107` is not authorized to send mail for `meddefense-portal.com`.
- **DKIM:** None - No DKIM signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation indicates `action=none` due to SPF failure and missing DKIM signing.
- **Authentication verdict:** Fail - Technical authentication checks failed.
- **Investigation meaning:** The failure of SPF and DMARC indicates that the message originated from sending infrastructure not authorized for `meddefense-portal.com`. Additionally, `meddefense-portal.com` is an external domain distinct from the primary domain `meddefense.com`.

## Email 3 - outlook-protection.com

- **SPF:** Pass - Sending IP `51.38.42.17` is authorized by the SPF record published for `outlook-protection.com`.
- **DKIM:** Pass - The message contains a DKIM signature matching domain `outlook-protection.com`.
- **DMARC:** Pass - DMARC passes with `action=none` because the `From:` header domain aligns with the authenticated domain `outlook-protection.com`.
- **Authentication verdict:** Pass - Technical authentication passes for the sending domain.
- **Investigation meaning:** Passing SPF, DKIM, and DMARC demonstrates that the email originated from infrastructure authorized for `outlook-protection.com`. However, passing technical authentication does not establish that the message is safe or trustworthy. Passing authentication merely indicates domain alignment for the sender's own domain; it does not indicate legitimate brand authorization, as `outlook-protection.com` is not the same as `microsoft.com` or `outlook.com`.

## Email 4 - meddefense.com

- **SPF:** Pass - Sending IP `10.10.1.15` is authorized to deliver mail on behalf of `meddefense.com`.
- **DKIM:** Pass - The message contains a valid DKIM signature aligned with domain `meddefense.com`.
- **DMARC:** Pass - DMARC evaluation indicates `action=none`, fully aligning with domain `meddefense.com`.
- **Authentication verdict:** Pass - Technical authentication aligns with the organizational domain.
- **Investigation meaning:** Authentication results indicate that the message originated from sending infrastructure authorized for `meddefense.com`, supporting domain alignment with internal mail infrastructure.

## Email 5 - medequip-supplies.net

- **SPF:** Softfail - Sending IP `185.176.43.22` returned a softfail evaluation for `medequip-supplies.net`.
- **DKIM:** None - No DKIM signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed with `action=none` due to unaligned SPF and absent DKIM signature.
- **Authentication verdict:** Fail - Technical authentication checks failed.
- **Investigation meaning:** The softfail SPF result and lack of DKIM signature indicate that the sending IP `185.176.43.22` is not designated as an authorized sender for `medequip-supplies.net`, contradicting the technical legitimacy of the sender address.

## Email 6 - canadian-pharma-discount.org

- **SPF:** Softfail - Sending IP `203.0.113.228` is not designated as an authorized sender for `canadian-pharma-discount.org`.
- **DKIM:** None - No DKIM signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation failed, resulting in `action=quarantine` as specified by the domain policy.
- **Authentication verdict:** Fail - Technical authentication checks failed.
- **Investigation meaning:** The message failed domain authentication alignment, triggering a DMARC policy action of quarantine. This indicates sending host origin outside the published domain policy.

## Email 7 - meddefense-benefits.org

- **SPF:** Fail - Sending IP `164.90.218.73` is not authorized for `meddefense-benefits.org`.
- **DKIM:** None - No DKIM signature is present in the email headers (`header.d=none`).
- **DMARC:** Fail - DMARC evaluation indicates `action=none` due to failed SPF and missing DKIM signature.
- **Authentication verdict:** Fail - Technical authentication checks failed.
- **Investigation meaning:** The email failed SPF and DMARC authentication checks. The sending IP `164.90.218.73` is not authorized by the record for `meddefense-benefits.org`, and the domain itself is distinct from `meddefense.com`.

## Email 8 - hhs.gov

- **SPF:** Pass - Sending IP `134.174.47.82` is authorized to transmit mail for `hhs.gov`.
- **DKIM:** Pass - The message contains a valid signature aligned with domain `hhs.gov`.
- **DMARC:** Pass - DMARC evaluation indicates `action=none`, showing full domain alignment with `hhs.gov`.
- **Authentication verdict:** Pass - Technical authentication is verified for the domain.
- **Investigation meaning:** Authentication checks indicate that the email was transmitted by infrastructure authorized for `hhs.gov`, supporting technical domain alignment.
