## 9. The Chain of Trust

### Part 1: Capturing and Analyzing the Full Certificate Chain

Using `openssl s_client -showcerts -connect`, we capture the multi-tier certificate chain for a commercial endpoint (e.g., `github.com`).

#### 1. Chain Structure Overview

* **Total Certificates in Chain:** 3 (Leaf, Intermediate CA, Root CA).
* **Certificate Roles:**
1. **Leaf Certificate:** Issued specifically to `github.com` for TLS session termination.
2. **Intermediate CA:** Issued by the Root CA to sign operational leaf certificates, isolating the high-security Root.
3. **Root CA:** Self-signed anchor embedded directly in client operating system trust stores.

#### 2. Subject and Issuer Chain Mapping

* **Certificate 1 (Leaf):**
* *Subject:* `CN = github.com, O = GitHub, Inc., L = San Francisco, ST = California, C = US`
* *Issuer:* `CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1, O = DigiCert Inc, C = US`
* **Certificate 2 (Intermediate CA):**
* *Subject:* `CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1, O = DigiCert Inc, C = US` *(Matches Leaf Issuer)*
* *Issuer:* `CN = DigiCert Global Root G2, O = DigiCert Inc, C = US`
* **Certificate 3 (Root CA):**
* *Subject:* `CN = DigiCert Global Root G2, O = DigiCert Inc, C = US` *(Self-signed; matches Intermediate Issuer)*
* *Issuer:* `CN = DigiCert Global Root G2, O = DigiCert Inc, C = US`


### Part 2: Manual Chain Verification

#### 1. Verification Commands and Results

```bash
# Verify the leaf certificate against the intermediate and root trust store
openssl verify -CAfile root_ca.pem -untrusted intermediate_ca.pem leaf_cert.pem

```

* *Output:* `leaf_cert.pem: OK`

```bash
# Attempt verification after removing the intermediate certificate
openssl verify -CAfile root_ca.pem leaf_cert.pem

```

* *Output Error:* `error 20 at 0 depth lookup: unable to get local issuer certificate`

#### 2. Why Servers Must Send the Full Chain

This failure demonstrates that client operating systems only store pre-approved **Root CAs**, not thousands of dynamic intermediates. If a web server transmits *only* its leaf certificate during a TLS handshake, the client browser cannot bridge the mathematical verification gap to the root anchor, resulting in a trust failure. Servers must send the complete intermediate chain so clients can validate the trust path instantly.

### Part 3: Revocation Mechanisms & MedDefense Incident Response

#### 1. CRL vs. OCSP vs. OCSP Stapling

* **CRL (Certificate Revocation List):** A periodically updated, cryptographically signed list published by a CA containing serial numbers of revoked certificates. **Limitation:** As the total volume of issued certificates grows, CRL file sizes bloat massively, causing high download overhead and delayed revocation awareness.
* **OCSP (Online Certificate Status Protocol):** Enables clients to query a CA's server directly for the real-time revocation status of a specific certificate via an HTTP request. **Improvement:** Eliminates large file downloads by returning immediate "good", "revoked", or "unknown" responses.
* **OCSP Stapling:** Allows the web server itself to periodically fetch a signed OCSP response from the CA and "staple" it directly into the initial TLS handshake. This relieves the CA from handling massive query traffic spikes while protecting client privacy and improving handshake speed.

#### 2. MedDefense Portal Private Key Compromise Incident Response

If `web-srv-01`'s private key is exposed in a GitHub repository, execute this remediation sequence immediately:

1. **Revocation Request:** Contact the issuing CA via ACME protocol or web portal to instantly revoke the compromised certificate, triggering updates to the CA's CRL and OCSP endpoints.
2. **Key Generation:** Generate a brand-new, cryptographically secure private key on the secure server terminal (`openssl genpkey`).
3. **CSR Creation:** Generate a fresh Certificate Signing Request (`openssl req`) incorporating updated Subject Alternative Names.
4. **Issuance and Deployment:** Obtain the new certificate, bundle the full intermediate chain, update Nginx/Apache configuration on `web-srv-01`, and restart the web service.
5. **Audit & Post-Mortem:** Scan internal code repositories to purge leaked secrets, rotate administrative credentials, and enforce stricter pre-commit scanning.

### Part 4: Trust Store Exploration

#### 1. System Root CAs Inspection

* **Storage Location:** On standard Linux distributions, trusted root certificates reside in `/etc/ssl/certs/` or `/usr/share/ca-certificates/`.
* **Root Count:** Modern Linux trust stores typically contain **between 120 to 180 distinct trusted root CA certificates** pre-installed by default.

#### 2. Root CA Inspection Sample (`openssl x509`)

Inspecting a standard system root (e.g., DigiCert Global Root CA):

```bash
openssl x509 -in /etc/ssl/certs/DigiCert_Global_Root_CA.pem -text -noout

```

* **Validity Period:** Typically spans **15 to 20+ years** (e.g., Not Before: Nov 10 2006, Not After: Jan 15 2038).
* **Initial Impression:** This long-lived validity period often surprises security newcomers, but it is necessary because root certificates anchor entire public key infrastructures and cannot be rotated frequently without breaking global software ecosystems. Security is maintained by keeping root private keys offline in hardened hardware security modules (HSMs) and delegating short-lived operational signing to intermediate CAs.
