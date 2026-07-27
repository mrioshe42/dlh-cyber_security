## 16. The Cryptographic Attack Surface

### 1. TLS Downgrade

* **Attack:** TLS Downgrade
* **Mechanism:** An active Man-in-the-Middle (MITM) adversary intercepts the initial cryptographic handshake between a client and server, stripping support for modern protocols to force a fallback to legacy protocols like TLS 1.0.
* **MedDefense Vulnerability:** Patient Portal (`web-srv-01`).
* **Evidence:** Finding 005 (Support for deprecated TLS 1.0 protocol and legacy ciphers).
* **Viable Today:** **Yes.** Because the server accepts TLS 1.0 handshakes, an attacker on the network path can successfully force a downgrade and exploit underlying weaknesses like POODLE or BEAST.
* **Mitigation:** Completely disable TLS 1.0 and TLS 1.1 in the Nginx/web server configuration, strictly enforcing TLS 1.2 and TLS 1.3 with modern AEAD ciphers.

### 2. Collision Attack

* **Attack:** Collision Attack
* **Mechanism:** An attacker exploits mathematical weaknesses in weak hashing algorithms (such as MD5 or SHA-1) to generate two distinct inputs that produce an identical hash digest, potentially forging digital signatures or certificates.
* **MedDefense Vulnerability:** Domain Controller (`ad-dc-01`) legacy Kerberos ticketing.
* **Evidence:** Finding 020 / T6 analysis (Legacy cryptographic compatibility settings in Active Directory).
* **Viable Today:** **Yes (Theoretically/Historically).** While modern web certificates have migrated away from MD5/SHA-1, legacy directory services supporting older encryption types can still present weakened signature verification surfaces.
* **Mitigation:** Enforce strong cryptographic defaults across Active Directory domain functional levels, deprecating RC4 and old signature algorithms in favor of AES-256 and SHA-256/SHA-384.


### 3. Birthday Attack

* **Attack:** Birthday Attack
* **Mechanism:** A cryptographic attack rooted in the birthday paradox probability math (
$$\approx 1.2 \times \sqrt{N}$$


), which dramatically reduces the number of trials required to find a hash collision compared to brute-forcing a pre-image.
* **MedDefense Vulnerability:** Enterprise hashing implementations and password storage mechanisms utilizing short or weak hash functions.
* **Evidence:** T6 cryptographic primitives review across legacy internal web services.
* **Viable Today:** **Yes (As a mathematical vector against legacy hashes).** If MedDefense stores any passwords using un-salted MD5 or short hash outputs, rainbow tables and birthday collisions make cracking trivial.
* **Mitigation:** Utilize cryptographically strong, salt-backed key derivation functions like Argon2id or bcrypt for credentials, and enforce 256-bit or greater hash lengths (SHA-256+) for data integrity.

### 4. Kerberoasting

* **Attack:** Kerberoasting
* **Mechanism:** Any authenticated domain user requests a Service Ticket (TGS) for any service principal name (SPN) tied to a user account, extracts the ticket offline, and brute-forces the user's plaintext password using the ticket's RC4 or AES encryption key wrapper.
* **MedDefense Vulnerability:** Active Directory Domain Controller (`ad-dc-01`) and enterprise service accounts.
* **Evidence:** Finding 007 (LDAP Relay) and general IAM governance gaps (`IAM-02`).
* **Viable Today:** **Yes.** Standard domain user accounts with service principal names are fully susceptible to offline ticket harvesting and cracking if weak encryption types are permitted.
* **Mitigation:** Enforce AES encryption for Kerberos (`msss-ad-enforce-aes`), implement complex, long passwords (25+ characters) for service accounts, and deploy Group Managed Service Accounts (gMSAs) with automatic password rotation.

### 5. On-path / MITM on Unencrypted Channels

* **Attack:** On-path / Man-in-the-Middle (MITM)
* **Mechanism:** An attacker positioned on the local network intercepts unencrypted data streams flowing between internal systems, reading or modifying sensitive clinical traffic in transit.
* **MedDefense Vulnerability:** PACS imaging servers (`pacs-srv-01`), internal database links, and medical IoT monitors.
* **Evidence:** Finding 016 (Philips Monitor data stream exposure) and Net-04 flat network architecture.
* **Viable Today:** **Yes.** The flat network architecture (`Net-04`) allows any compromised workstation to ARP spoof or sniff unencrypted DICOM and database traffic traversing internal subnets.
* **Mitigation:** Implement network microsegmentation (VLANs), mandate TLS for all internal application-to-database connections, and deploy encrypted `DICOM-TLS` protocols across clinical imaging networks.

### 6. Key Recovery from Memory

* **Attack:** Key Recovery from Memory (RAM Scraping)
* **Mechanism:** An attacker who has achieved elevated root or administrator privileges on a host inspects physical memory or process space to extract cryptographic keys currently resident in RAM.
* **MedDefense Vulnerability:** Financial Database Server (`billing-srv-01`).
* **Evidence:** Finding 003 (SQLi / EOL OS compromise vector) combined with root-level access.
* **Viable Today:** **Yes.** If an attacker achieves root access on `billing-srv-01`, software-managed encryption keys sitting unencrypted in application memory can be dumped or scraped.
* **Mitigation:** Offload key management to an external Hardware Security Module (HSM) or cloud KMS where keys are processed inside secure hardware boundaries and never exposed in host OS application memory.
