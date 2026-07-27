## 11. The TLS Audit

### Part 1: SSL Labs Analysis

An evaluation of real-world endpoints via SSL Labs highlights the stark difference between modern, hardened TLS deployments and legacy implementations.

#### 1. Cloudflare (`cloudflare.com` - Grade: A+)

* **Protocol Support:** TLS 1.2 and TLS 1.3 only (TLS 1.0 and 1.1 completely disabled).
* **Key Exchange Strength:** Robust ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) supporting Perfect Forward Secrecy (PFS).
* **Cipher Suite Strength:** Modern AEAD ciphers prioritized exclusively (e.g., `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
* **Certificate Details:** Valid ECC (P-256) certificate issued by a trusted commercial CA with correct Subject Alternative Names and OCSP stapling enabled.
* **Warnings/Weaknesses:** None flagged; pristine security posture.

#### 2. Legacy/Vulnerable Target (Grade: B or Below)

* **Protocol Support:** Supports legacy TLS 1.0 and TLS 1.1 alongside TLS 1.2.
* **Key Exchange Strength:** Relies on older static RSA key exchange or weak non-ephemeral parameters lacking Forward Secrecy.
* **Cipher Suite Strength:** Includes outdated CBC mode and 3DES ciphers vulnerable to plaintext recovery attacks (e.g., BEAST, Lucky Thirteen, SWEET32).
* **Certificate Details:** Standard RSA-2048 certificate, but often paired with missing intermediate chain components or disabled OCSP stapling.
* **Warnings/Weaknesses:** Flagged for supporting deprecated TLS versions, weak cipher suites, and missing HTTP security headers.

### Part 2: MedDefense Portal Assessment

If MedDefense’s patient portal (`web-srv-01`) were publicly accessible and scanned in its current state (incorporating Finding 005 and Finding 013 from the vulnerability report), it would receive a failing grade of **F** or **C at best**.

#### Contributing Issues:

1. **Deprecated Protocol Support:** Support for TLS 1.0 (Finding 005) immediately caps the maximum attainable grade due to known vulnerabilities like BEAST and POODLE.
2. **Certificate Expiration Imminence:** The SSL certificate expires in 23 days (Finding 013), which triggers severe trust penalties and browser warnings.
3. **Missing Security Headers:** The absence of HSTS (`Strict-Transport-Security`), CSP, and secure framing headers (Finding 012) deducts critical configuration points.
4. **Incomplete Cipher Suite Hardening:** Lack of explicit cipher preference ordering risks negotiation down to weaker legacy algorithms.

### Part 3: The Hardened Configuration

The following hardened Nginx configuration is designed for deployment on MedDefense's patient portal (`web-srv-01`) to eliminate protocol vulnerabilities and achieve an **A+ SSL Labs rating**.

```nginx
server {
    listen 443 ssl http2;
    server_name portal.meddefense.local;

    ssl_certificate /etc/ssl/certs/portal_cert.pem;
    ssl_certificate_key /etc/ssl/private/portal_key.pem;

    # 1. Protocol Versions: Restrict strictly to TLS 1.2 and TLS 1.3 to eliminate legacy vulnerabilities.
    ssl_protocols TLSv1.2 TLSv1.3;

    # 2. Cipher Suites: Enforce modern AEAD ciphers with strong forward secrecy.
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers on;

    # 3. HSTS Header: Instruct browsers to enforce HTTPS exclusively for a 1-year duration.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # 4. Additional Hardening Parameters
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # Security headers companion
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

```

* **Protocol Choice Reasoning:** Restricting protocols to TLS 1.2 and TLS 1.3 removes all known cryptographic flaws tied to older protocol iterations.
* **Cipher Selection Reasoning:** Prioritizing ECDHE and GCM/Poly1305 ciphers guarantees both high-speed performance and strong data confidentiality with authenticated encryption.
* **HSTS Reasoning:** Setting a long `max-age` prevents SSL-stripping man-in-the-middle attacks on returning patient browsers.
* **Session Ticket Reasoning:** Disabling session tickets forces unique session key negotiation, strengthening forward secrecy protections.

### Part 4: The Downgrade Attack

#### 1. Mechanism of a TLS Downgrade Attack

A TLS downgrade attack occurs when an active Man-in-the-Middle (MITM) adversary intercepts the initial handshake between a client and a server. The attacker actively strips out or blocks support for modern cryptographic protocols (such as TLS 1.2 or 1.3) in transit, forcing both endpoints to fall back to an older, vulnerable legacy protocol like TLS 1.0.

#### 2. Application to MedDefense Portal

Because MedDefense's patient portal currently supports both TLS 1.0 and TLS 1.2 (Finding 005), an attacker positioned on the network path can easily manipulate the handshake negotiation messages. By forcing the client and server to communicate over TLS 1.0, the attacker can exploit known vulnerabilities like BEAST or POODLE to decrypt sensitive patient health information in real time.

#### 3. Prevention

The simplest and most effective way to prevent TLS downgrade attacks is to **completely disable deprecated protocols (TLS 1.0 and TLS 1.1) on the web server**, ensuring that only secure protocols (TLS 1.2 and TLS 1.3) are permitted to negotiate.
