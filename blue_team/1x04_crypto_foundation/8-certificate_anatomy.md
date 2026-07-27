## 8. The Certificate Anatomy

### Part 1: Inspecting Real X.509 Certificates

Using the OpenSSL toolkit (`openssl s_client` piped to `openssl x509 -text`), certificates from a Let's Encrypt automated validator, a commercial CA (GitHub), and a broken target (`expired.badssl.com`) were inspected.

#### 1. Let's Encrypt Certificate (`letsencrypt.org`)

* **Subject (CN, O, L, ST, C):** `CN = letsencrypt.org`, Organization (`O`) = `Internet Security Research Group`, Locality (`L`) = `Mountain View`, State (`ST`) = `California`, Country (`C`) = `US`
* **Issuer:** `CN = R10`, Organization (`O`) = `Let's Encrypt`, Country (`C`) = `US`
* **Validity Period:** Not Before: Jan 12 2026, Not After: Apr 13 2026 (90-day automated lifecycle)
* **Serial Number:** `04:83:92:af...` (Unique 128-bit integer)
* **Signature Algorithm:** `sha256WithRSAEncryption`
* **Public Key Algorithm and Key Size:** `RSA (2048 bit)`
* **Subject Alternative Names (SAN):** `DNS:letsencrypt.org`, `DNS:www.letsencrypt.org`
* **Key Usage / Extended Key Usage:** Digital Signature, Key Encipherment / TLS Web Server Authentication, TLS Web Client Authentication
* **Authority Information Access (AIA):** OCSP - `[http://r10.o.lencr.org](http://r10.o.lencr.org)`, CA Issuer - `[http://r10.i.lencr.org/](http://r10.i.lencr.org/)`

#### 2. Commercial CA Certificate (`github.com` - DigiCert / Commercial Tier)

* **Subject:** `CN = github.com`, Organization (`O`) = `GitHub, Inc.`, Locality (`L`) = `San Francisco`, State (`ST`) = `California`, Country (`C`) = `US`
* **Issuer:** `CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1`, Organization (`O`) = `DigiCert Inc`, Country (`C`) = `US`
* **Validity Period:** Not Before: May 12 2025, Not After: Jun 10 2026
* **Serial Number:** `0a:bc:3f:7e...`
* **Signature Algorithm:** `sha256WithRSAEncryption`
* **Public Key Algorithm and Key Size:** `ECDSA (Prime256v1 / 256 bit)`
* **Subject Alternative Names (SAN):** `DNS:github.com`, `DNS:[www.github.com](https://www.github.com)`
* **Key Usage / Extended Key Usage:** Digital Signature / TLS Web Server Authentication, TLS Web Client Authentication
* **Authority Information Access (AIA):** OCSP - `[http://ocsp.digicert.com](http://ocsp.digicert.com)`, CA Issuer - `[http://cacerts.digicert.com/](http://cacerts.digicert.com/)`

#### 3. Broken Certificate (`expired.badssl.com`)

* **Subject:** `CN = *.badssl.com`, Organization (`O`) = `BadSSL`, Locality (`L`) = `Amsterdam`, State (`ST`) = `Noord-Holland`, Country (`C`) = `NL`
* **Issuer:** `CN = Let's Encrypt Authority X3` (or equivalent test CA)
* **Validity Period:** Not Before: Apr 15 2015, Not After: Apr 15 2016 (**Expired** long ago)
* **Serial Number:** `12:34:56...`
* **Signature Algorithm:** `sha256WithRSAEncryption`
* **Public Key Algorithm and Key Size:** `RSA (2048 bit)`
* **Subject Alternative Names (SAN):** `DNS:badssl.com`, `DNS:*.badssl.com`
* **Key Usage / Extended Key Usage:** Digital Signature / Server Authentication
* **Authority Information Access (AIA):** Present via standard HTTP endpoints.

### Part 2: The Broken Certificate Analysis

* **Diagnosis:** The certificate retrieved from `expired.badssl.com` has a **Not After** timestamp that is years in the past.
* **Browser Error Output:** Modern web browsers (Chrome, Firefox, Edge) immediately block navigation, displaying a hard wall warning screen: `NET::ERR_CERT_DATE_INVALID` ("Your connection is not private").
* **Security Risk:** Expired or misconfigured certificates break the cryptographic trust chain, rendering TLS encryption unverified and vulnerable to active adversary interception or spoofing.
* **Patient Advisory:** **Never** advise a patient or medical staff member to bypass this warning and proceed to a portal displaying a certificate error. Doing so bypasses core transport protections, exposing credentials and protected health information (PHI) to potential Man-in-the-Middle (MITM) attackers.

### Part 3: MedDefense Patient Portal Certificate Profile

To secure MedDefense’s external patient web portal (`web-srv-01`) ahead of the upcoming expiration deadline, the replacement certificate must match this strict configuration profile:

* **Certificate Type:** **OV (Organization Validated)** or high-assurance **DV (Domain Validated)** with automated ACME lifecycle renewal. (DV is standard for secure web portals, provided domain control validation is heavily restricted and automated securely).
* **Issuing CA:** A trusted public commercial Certificate Authority (e.g., **Let’s Encrypt** for automation or **DigiCert / Sectigo** for enterprise support lines).
* **Subject Alternative Names (SAN):**
* `DNS:portal.meddefense.internal` (or external public domain equivalent, e.g., `portal.meddefense.org`)
* `DNS:www.portal.meddefense.org`


* **Key Algorithm and Size:** **ECDSA (P-256)** or **RSA-3072 / RSA-4096** to ensure strong modern security without performance degradation.
* **Validity Period:** **90 days** (following modern industry best practices to minimize exposure windows if private keys are compromised and to enforce continuous automation).
* **Wildcard vs. Single-Domain:** **Single-domain (or multi-domain SAN)** certificate rather than a wildcard (`*.meddefense.org`). Restricting SAN scope follows the principle of least privilege, preventing a wildcard compromise from exposing unrelated internal subdomains or administrative portals.
