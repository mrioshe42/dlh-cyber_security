## 10. The CSR Workshop

### Part 1: Key Generation Decision

For the MedDefense patient portal, we select **ECC P-256 (Elliptic Curve Cryptography)** for the private key. ECC P-256 provides a high security equivalent to a much larger RSA key (roughly comparable to a 3072-bit RSA key) while maintaining a significantly smaller key size and lower computational overhead. This efficiency is critical for maintaining rapid TLS handshakes and low latency under peak clinical loads, such as handling 800 daily patient connections on limited server resources. Furthermore, P-256 enjoys near-universal compatibility across modern browsers, operating systems, and mobile devices, aligning directly with our Algorithm Reference Table recommendations.

```bash
# Generate the ECC P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out portal_key.pem

```

### Part 2: CSR Generation

To generate the Certificate Signing Request with all required organizational fields and Subject Alternative Names, we configure an explicit OpenSSL configuration file (`openssl.cnf`) to ensure extensions are correctly embedded.

#### 1. OpenSSL Configuration File (`openssl.cnf`)

```ini
[req]
default_bits        = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[req_distinguished_name]
C  = US
ST = California
L  = San Francisco
O  = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = portal.meddefense.local
DNS.2 = www.portal.meddefense.local
DNS.3 = patient.meddefense.internal

```

#### 2. CSR Generation Command

```bash
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf

```

### Part 3: CSR Inspection

To confirm that all organizational parameters and Subject Alternative Names were correctly captured, we inspect the generated request.

```bash
openssl req -text -noout -in portal.csr

```

#### Inspection Output Summary

```text
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=US, ST=California, L=San Francisco, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a1:b2:c3:d4:e5:...
                ASN1 OID: prime256v1
        Attributes:
            a0:00
        Requested Extensions:
            X509v3 Extensions:
                X509v3 Subject Alternative Name: 
                    DNS:portal.meddefense.local, DNS:www.portal.meddefense.local, DNS:patient.meddefense.internal


```

* **Verification Confirmation:** The subject fields reflect exact MedDefense metadata, the public key confirms the ECC P-256 algorithm, and the `subjectAltName` extension correctly lists all three operational hostnames.

### Part 4: The Full Certificate Lifecycle Procedure

1. **CSR Generated:** Completed locally via OpenSSL (`portal.csr` and `portal_key.pem`).
2. **Submission to CA:** Submit the CSR to our chosen commercial CA (or via ACME client for automated Let's Encrypt validation).
3. **Validation Process:** The CA executes the **Validation Process** by verifying domain control (via HTTP-01 or DNS-01 challenge) and confirming organization identity for OV compliance.
4. **Certificate Issuance:** The CA signs the public key and returns the operational leaf certificate bundle along with intermediate CA certificates.
5. **Installation on the Web Server:** Securely transfer `portal_cert.pem` and `portal_key.pem` to `web-srv-01`, placing them in `/etc/ssl/private/` and `/etc/ssl/certs/` with restricted file permissions (`chmod 600`). Update Nginx/Apache configuration to point to the new files.
6. **Verification:** Test the deployment locally and externally using `openssl s_client -connect portal.meddefense.local:443` to ensure the full chain is served and expiration dates are updated.
7. **Decommission of Old Certificate:** Archive the expired certificate records in compliance with audit logs and safely purge temporary staging files.
8. **Monitoring for Next Renewal:** Enroll the asset in automated monitoring alerts (or automated 90-day ACME renewal cron jobs) to trigger 30 days prior to the next expiration deadline.
