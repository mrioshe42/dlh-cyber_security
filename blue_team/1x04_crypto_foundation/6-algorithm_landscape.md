## 6. The Algorithm Landscape

### Algorithm Reference Table

| Field | Algorithm | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
| --- | --- | --- | --- | --- | --- | --- |
| **Symmetric** | AES-128 | 128 bits | Bulk data encryption | Current | N/A | Permitted for general internal file storage; superseded by AES-256 for regulated PHI. |
| **Symmetric** | AES-192 | 192 bits | Bulk data encryption | Current | N/A | Available alternative for balanced performance and high security. |
| **Symmetric** | AES-256 | 256 bits | High-security data encryption | Current | N/A | **Mandatory Standard:** PostgreSQL database (`ehr-db-01`), NAS backups (`NAS-01`), and sensitive exports. |
| **Symmetric** | DES | 56 bits | Legacy block cipher | Broken | Exhaustive key search is trivial on modern hardware (broken since 1999). | **Active Vulnerability:** Enabled in Active Directory (`ad-dc-01/02`) for legacy compatibility (Finding 018). |
| **Symmetric** | 3DES | 112 / 168 bits | Legacy encryption | Deprecated | Small block size makes it vulnerable to SWEET32 collision attacks. | Phased out across all systems; must be disabled in legacy TLS and network profiles. |
| **Symmetric** | ChaCha20-Poly1305 | 256 bits | High-speed stream encryption / AEAD | Current | N/A | **Recommended Alternative:** Modern TLS cipher suites and resource-constrained environments. |
| **Symmetric** | RC4 | 40–128 bits | Stream cipher | Broken | Flaws in key stream generation allow plaintext recovery (used in old TLS/WLAN). | **Active Vulnerability:** Active Directory Kerberos tickets supporting RC4/MD4 (Finding 018). |
| **Symmetric** | Blowfish | 32–448 bits | Symmetric block cipher | Deprecated | Small 64-bit block size makes it vulnerable to birthday attacks (e.g., SWEET32). | Historically used in legacy applications; superseded by AES and modern KDFs like bcrypt. |
| **Asymmetric** | RSA-2048 | 2048 bits | Key exchange, digital signatures | Current | N/A | **Active Usage:** Patient portal TLS certificates (`web-srv-01`) and SSH server authentication. |
| **Asymmetric** | RSA-4096 | 4096 bits | Long-term secure signatures / root CAs | Current | N/A | **Recommended Usage:** Internal root and intermediate Certificate Authority (PKI) architecture. |
| **Asymmetric** | ECC P-256 | 256 bits (Curve) | Key exchange, digital signatures | Current | N/A | **Recommended Usage:** Modern web traffic and resource-constrained medical IoT (`Alaris Pumps`). |
| **Asymmetric** | ECC P-384 | 384 bits (Curve) | High-security asymmetric operations | Current | N/A | **Recommended Usage:** High-assurance internal administrative server communications. |
| **Asymmetric** | Diffie-Hellman | Variable (e.g., 2048-bit) | Key establishment over insecure channels | Current | N/A (when authenticated) | Base protocol for site-to-site VPN tunnels (FortiGate Central-to-Westside). |
| **Asymmetric** | ECDHE | Curve-based | Ephemeral key exchange with PFS | Current | N/A | **Mandatory Standard:** Patient portal TLS configuration for Perfect Forward Secrecy. |
| **Hash** | MD5 | 128 bits | Cryptographic checksums | Broken | Vulnerable to fast collision attacks (collisions found in seconds). | **Active Vulnerability:** Active Directory NTHash format (`ad-dc-01/02`) and legacy integrity checks. |
| **Hash** | SHA-1 | 160 bits | Cryptographic hashing / digital signatures | Broken | Practical collision attacks demonstrated (SHAttered); deprecated globally. | Phased out; must be completely purged from internal certificate chains and code signing. |
| **Hash** | SHA-256 | 256 bits | Integrity, signatures, certificates | Current | N/A | **Standard Hash:** File integrity verification, digital signatures (`5-sign_verify.sh`), and TLS certs. |
| **Hash** | SHA-512 | 512 bits | High-security hashing | Current | N/A | Optional high-security integrity hashing for critical system images and logs. |
| **Hash** | SHA-3 | Variable (256/512) | Modern cryptographic hashing | Current | N/A | Advanced alternative cryptographic hashing conforming to NIST FIPS 202 standards. |
| **Key Derivation** | PBKDF2 | Variable iterations | Password-based key derivation | Current | N/A | Standard key derivation function for web applications and password hashing wrappers. |
| **Key Derivation** | bcrypt | Variable cost factor | Password hashing | Current | N/A | **Recommended Usage:** Web application user authentication and local credential stores. |
| **Key Derivation** | Argon2 | Variable parameters | Memory-hard password hashing | Current | N/A | **Mandatory Standard:** Next-generation enterprise password hashing for web portals. |
| **Key Derivation** | scrypt | Variable parameters | Memory-hard key derivation | Current | N/A | Alternative memory-hard hashing function for specialized encryption key derivation. |

---

### MedDefense Crypto Gap Analysis

Comparing current MedDefense infrastructure (from the T0 audit, 1x02 vulnerability scan findings, and risk register) against modern security standards reveals several critical cryptographic failures. Below are four key cases where MedDefense utilizes deprecated or broken algorithms, alongside their specific required replacements:

1. **Active Directory Kerberos Authentication (DES / RC4 / MD4)**
* **Current Usage:** Active Directory domain controllers (`ad-dc-01/02`) retain support for DES and RC4 encryption types, relying on MD4-based NTHash internally (Finding 018).
* **Security Risk:** Enables Kerberoasting and trivial offline brute-force attacks.
* **Recommended Replacement:** Disable DES and RC4 entirely via Group Policy; enforce **AES-256-CTS-HMAC-SHA1** (or modern AES kerberos keys) exclusively across all domain objects and service principals.


2. **Patient Portal Transport Layer Security (TLS 1.0)**
* **Current Usage:** Patient portal (`web-srv-01`) supports deprecated TLS 1.0 alongside TLS 1.2, leaving endpoints vulnerable to downgrade and side-channel attacks (Finding 005).
* **Security Risk:** Exposes external patient traffic to BEAST, POODLE, and Lucky Thirteen exploits.
* **Recommended Replacement:** Disable TLS 1.0 and TLS 1.1 immediately; enforce **TLS 1.3** with strict fallback limited to **TLS 1.2** using robust cipher suites (`ECDHE-ECDSA-AES256-GCM-SHA384`).


3. **Database Storage At Rest (Plaintext Ext4 Filesystem)**
* **Current Usage:** PostgreSQL EHR database (`ehr-db-01`) and MySQL billing database (`billing-srv-01`) store patient records and financial data in unencrypted plaintext on local ext4 disks.
* **Security Risk:** Complete data exposure upon physical drive extraction or root-level compromise (`RISK-001`, `RISK-002`, Finding 003).
* **Recommended Replacement:** Implement **LUKS2 disk encryption** (`aes-xts-plain64` with a 512-bit key) combined with database-level **AES-256** transparent data encryption.


4. **Medical Imaging Transmission (Unencrypted DICOM)**
* **Current Usage:** DICOM medical imaging traffic flows in cleartext over ports 4242 and 11112 between the Windows XP MRI workstation, clinical workstations, and the PACS server (`pacs-srv-01`).
* **Security Risk:** Violation of HIPAA privacy rules; patient identifiers and clinical imaging headers are fully readable via network packet capture (Finding 016).
* **Recommended Replacement:** Implement **DICOM TLS (DICOM PS3.15)** utilizing **AES-256-GCM** and mutual certificate authentication across all imaging nodes, isolating the legacy Windows XP workstation behind an inline micro-firewall.
