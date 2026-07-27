## 2. The Asymmetric Engine

### Part 1: RSA Key Generation, Encryption, and Limitations

To establish identity authentication and secure key exchange mechanisms for MedDefense administrative and patient portals, we implement standard RSA-2048 operations.

#### Key Generation and Small File Handling

```bash
# Generate RSA private key
openssl genrsa -out rsa_private.pem 2048

# Extract public key
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem

# Encrypt the patient record sample using public key
openssl pkeyutl -encrypt -in patient_sample.txt -inkey rsa_public.pem -pubin -out patient_sample.rsa.enc

# Decrypt using private key
openssl pkeyutl -decrypt -in patient_sample.rsa.enc -inkey rsa_private.pem -out patient_sample_rsa_decrypted.txt

```

#### Large File Encryption Test ($100\text{MB}$)

```bash
openssl pkeyutl -encrypt -in testfile -inkey rsa_public.pem -pubin -out testfile.rsa.enc

```

* **Observed Error Message:**
`rsautl verify failure` / `data greater than mod len` (or `Error: key size too small for encrypted data block`).
* **Technical Explanation:** Asymmetric algorithms like RSA rely on complex modular arithmetic whose maximum input block size is strictly bounded by the modulus length (e.g., 2048 bits / 256 bytes minus padding overhead). Direct asymmetric encryption cannot process large data streams. In real-world enterprise architectures, attempting to use RSA for bulk data encryption would cause complete application failure, making it exclusively viable for securely exchanging small random symmetric keys or signing digital hashes.

### Part 2: ECC Key Generation & Resource Efficiency

Elliptic Curve Cryptography offers robust asymmetric security profiles with drastically reduced mathematical overhead.

#### ECC Key Generation Commands

```bash
# Generate ECDSA/ECDH private key
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem

# Extract ECC public key
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem

```

#### Comparative File Size & Operational Analysis

* **File Size Comparison:** Inspecting `rsa_private.pem` (~1.7 KB) versus `ecc_private.pem` (~220 bytes) demonstrates an approximate **8:1 storage and transmission efficiency ratio**.
* **Resource Constraints & Medical IoT:** ECC achieves equivalent security strength to RSA using exponentially smaller keys (e.g., a 256-bit ECC key provides security comparable to a 3072-bit RSA key). This drastically lowers CPU cycles, memory allocation, and battery utilization during handshakes. For MedDefense infrastructure supporting constrained clinical devices—such as embedded Windows XP MRI workstations, BD Alaris infusion pumps, and Philips vital signs monitors—ECC enables modern cryptographic authentication without crashing legacy processors.

### Part 3: The Hybrid Model in Enterprise TLS

The hybrid model combines the strengths of both cryptographic paradigms into a single unified protocol flow. Asymmetric encryption is utilized initially during the secure handshake to authenticate endpoints and securely exchange a temporary, high-speed symmetric session key. Once this secret key is mutually established, both systems switch entirely to symmetric encryption (such as AES-GCM or ChaCha20) for all subsequent bulk data transfer.

This combination is vastly superior because it solves the key distribution problem securely over untrusted networks while maintaining the high computational throughput required for large volumes of traffic. Applied to the MedDefense patient portal (`web-srv-01`), the HTTPS/TLS handshake (handled via RSA/ECC and ephemeral Diffie-Hellman) establishes the secure session and negotiates keys, while AES bulk encryption protects the actual transmission of clinical lab results and patient portal forms.

### Part 4: Comprehensive Cryptographic Key Length & Compliance Matrix

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Healthcare Usage |
| --- | --- | --- | --- | --- | --- |
| **AES** | Symmetric | 128, 192, 256 bits | 128 to 256 bits | **Approved** | **Mandatory Standard:** PostgreSQL database at rest, NAS backup encryption, and internal secure storage. |
| **RSA** | Asymmetric | 2048, 3072, 4096 bits | 112 to 128+ bits | **Approved** (2048+) | **Active:** Patient portal TLS certificates, SSH server authentication, and legacy integration handshakes. |
| **ECC** | Asymmetric | P-256, P-384, P-521 | 128 to 256 bits | **Approved** | **Recommended:** Modern TLS cipher suites and resource-constrained medical asset communication channels. |
| **ChaCha20-Poly1305** | Symmetric (AEAD) | 256 bits | 256 bits | **Approved** | **Permitted Alternative:** High-performance stream encryption for modern web traffic and mobile endpoints. |
| **DES** | Symmetric | 56 bits | 56 bits (Broken) | **Disallowed** | **Prohibited (Critical Gap):** Legacy Active Directory authentication bindings (must be fully purged). |
| **3DES** | Symmetric | 112 / 168 bits | 112 bits | **Deprecated / Disallowed** | **Prohibited:** Legacy compatibility channels; phased out entirely under current NIST/HIPAA guidelines. |
| **RC4** | Symmetric | 40 to 128 bits | Broken | **Disallowed** | **Prohibited (Critical Gap):** Legacy Kerberos service tickets (`ad-dc-01/02`) vulnerable to Kerberoasting. |
