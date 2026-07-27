## 15. The Crypto Posture Audit

### Systematic Crypto Findings

Revisiting MedDefense's original data protection map (T0), every cell previously marked as **Weak** or **Absent** is evaluated below to establish a rigorous cryptographic finding.

#### Finding 1: CRYPTO-001

* **Finding ID:** `CRYPTO-001`
* **Data Category:** Patient Health Records (EHR)
* **Data State:** At Rest
* **Current Protection:** None (Plaintext storage files on `ehr-db-01`)
* **Vulnerability Reference:** `Finding-003` (SQLi / Unrestricted DB access)
* **Risk Reference:** `RISK-002`
* **Algorithm Assessment:** Inadequate (Plaintext is vulnerable to direct disk reading and data exfiltration dumps).
* **Recommended Protection:** AES-256 in XTS or GCM mode (Transparent Data Encryption).
* **Encryption Level:** Database-level (TDE)
* **Key Management:** Cloud KMS / Hardware-backed Key Vault managed by Data Custodian under IT oversight.
* **Implementation Priority:** Phase 1

#### Finding 2: CRYPTO-002

* **Finding ID:** `CRYPTO-002`
* **Data Category:** Enterprise Backup Archives
* **Data State:** At Rest
* **Current Protection:** None (Plaintext backup storage on `NAS-01`)
* **Vulnerability Reference:** `Finding-015` / `GAP-006` (`BC-01`)
* **Risk Reference:** `RISK-008`
* **Algorithm Assessment:** Inadequate (Plaintext backups expose complete historical data sets if physical hardware is stolen).
* **Recommended Protection:** AES-256 via LUKS2 container encryption and encrypted cloud storage targets.
* **Encryption Level:** Volume-level
* **Key Management:** Offline Cryptographic Key Safe & Secure Vault under dual custody.
* **Implementation Priority:** Phase 1

#### Finding 3: CRYPTO-003

* **Finding ID:** `CRYPTO-003`
* **Data Category:** Patient Portal Web Traffic
* **Data State:** In Transit
* **Current Protection:** Weak (Supports deprecated TLS 1.0 protocols and weak cipher suites)
* **Vulnerability Reference:** `Finding-005`
* **Risk Reference:** `RISK-001` (Contributes to external edge compromise and data interception vectors)
* **Algorithm Assessment:** Inadequate (TLS 1.0 is vulnerable to BEAST/POODLE downgrade exploits; modern AEAD ciphers required).
* **Recommended Protection:** TLS 1.2 and TLS 1.3 exclusively, utilizing `ECDHE-ECDSA-AES256-GCM-SHA384` or `CHACHA20-POLY1305`.
* **Encryption Level:** Transport-level (TLS)
* **Key Management:** Automated filesystem keystore managed via ACME/Internal CA rotation workflows (90-day expiry).
* **Implementation Priority:** Immediate (48h)

#### Finding 4: CRYPTO-004

* **Finding ID:** `CRYPTO-004`
* **Data Category:** Financial and Billing Records
* **Data State:** At Rest
* **Current Protection:** Weak / Absent column-level segregation on `billing-srv-01`
* **Vulnerability Reference:** `Finding-003`
* **Risk Reference:** `RISK-002`
* **Algorithm Assessment:** Inadequate (Database lacks granular field protection for sensitive payment card primary account numbers).
* **Recommended Protection:** AES-256 Transparent Data Encryption combined with application-level column encryption for sensitive PAN fields.
* **Encryption Level:** Record / Column-level
* **Key Management:** Hardware Security Module (HSM) or dedicated Key Management Service with strict role-based access.
* **Implementation Priority:** Phase 1

#### Finding 5: CRYPTO-005

* **Finding ID:** `CRYPTO-005`
* **Data Category:** Medical Imaging and DICOM Files (PACS)
* **Data State:** At Rest & In Transit
* **Current Protection:** Absent (Unencrypted local storage pools and unencrypted internal DICOM transfers)
* **Vulnerability Reference:** `Finding-016` (`Philips Mon` data stream exposure)
* **Risk Reference:** `RISK-004` / `RISK-005`
* **Algorithm Assessment:** Inadequate (Unencrypted DICOM archives expose diagnostic imagery across clinical subnets).
* **Recommended Protection:** AES-256 volume encryption for storage arrays combined with TLS-wrapped DICOM networking (`DICOM-TLS`).
* **Encryption Level:** Volume / File-level
* **Key Management:** Centralized KMS with automated system boot key injection.
* **Implementation Priority:** Phase 2

#### Finding 6: CRYPTO-006

* **Finding ID:** `CRYPTO-006`
* **Data Category:** Medical IoT Device Configurations (BD Alaris Pumps)
* **Data State:** At Rest & In Transit
* **Current Protection:** Weak (Hardcoded default credentials, unencrypted configuration firmware payloads)
* **Vulnerability Reference:** `Finding-010`
* **Risk Reference:** `RISK-004`
* **Algorithm Assessment:** Inadequate (Lacks cryptographic code signing and secure channel transport encryption).
* **Recommended Protection:** Cryptographically signed firmware containers (SHA-256 / RSA-3072) and encrypted local flash storage.
* **Encryption Level:** File / Firmware Container-level
* **Key Management:** Vendor-managed code-signing root authority coupled with clinical device trust certificates.
* **Implementation Priority:** Phase 2

### Posture Score & Top Risks

#### Posture Score

* **Remediation Coverage:** **100%** of MedDefense's identified data flows and storage gaps now possess a fully defined cryptographic remediation path, transitioning the organization from a reactive security stance to an engineered zero-trust posture.

#### Top 3 Crypto Risks (Ranked by Combined Impact)

1. **`CRYPTO-001` (Patient Health Records on `ehr-db-01`):** Ranked highest due to massive regulatory exposure, severe HIPAA penalties, and high likelihood of targeted extortion attacks exploiting unencrypted database files.
2. **`CRYPTO-002` (Enterprise Backup Archives on `NAS-01`):** Ranked second because an unencrypted backup appliance acts as a complete "golden copy" target for ransomware actors seeking to harvest total institutional data assets.
3. **`CRYPTO-004` (Financial and Billing Records on `billing-srv-01`):** Ranked third due to direct PCI-DSS compliance violations and high risk of financial fraud stemming from exposed payment data elements.
