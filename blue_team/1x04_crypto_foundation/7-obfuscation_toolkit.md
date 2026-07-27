## 7. The Obfuscation Toolkit

### Part 1: Technique Comparison

| Technique | What it does to the data | Recovery Status & Authority | Concrete Healthcare Use Case |
| --- | --- | --- | --- |
| **Encryption** | Transforms plaintext into ciphertext using an algorithmic key. | **Reversible:** Only recoverable by authorized parties possessing the correct cryptographic key. | Storing patient medical records in the PostgreSQL database (`ehr-db-01`) at rest. |
| **Hashing** | Maps data of arbitrary size to a fixed-size bit string via a one-way mathematical function. | **Irreversibly Non-Reversible:** Cannot be reversed; can only be matched via brute-force or rainbow tables if weak. | Storing secure user authentication credentials and verifying file integrity. |
| **Tokenization** | Replaces sensitive data with a completely non-sensitive random surrogate (token) referencing a secure map. | **Reversible via Secure Lookup:** Recoverable only by authorized systems via an isolated secure token vault database. | Storing patient credit card numbers within the billing application (`billing-srv-01`). |
| **Data Masking** | Obscures parts of specific data elements while preserving the original format and structure for display. | **Irreversible for Viewers:** Intentionally hides data fragments from unauthorized roles permanently on display layers. | Displaying partial Social Security Numbers (`***-**-4321`) to administrative staff. |
| **Steganography** | Conceals the existence of secret data by embedding it directly inside another ordinary carrier file or medium. | **Reversible by Intended Receiver:** Recoverable by anyone who knows the extraction algorithm and secret parameters. | Unauthorized or covert exfiltration of patient health records hidden inside medical imaging files. |

### Part 2: MedDefense Tokenization Design

To process patient billing securely without exposing raw primary account numbers, MedDefense implements a structured tokenization model.

* **Data Tokenized and Format:** Primary Account Numbers (PAN) are replaced with a pseudo-random token string matching the exact format `TKN-UUID-4152` (preserving trailing 4 digits for merchant utility where required, e.g., `******-4152`).
* **Token Vault Storage and Protection:** The token-to-real-data mapping table is stored in a dedicated, hardened internal vault database isolated on a secure management segment (`db-vault-01`). The database leverages **AES-256-GCM** storage encryption, strict role-based access control (RBAC), and multi-factor authentication for administrative database logins.
* **Compromise Scenario Impact:** If the primary billing application frontend (`billing-srv-01`) is breached by a crypto-miner or attacker, **only non-sensitive tokens are exposed**, completely protecting raw financial cardholder data from direct theft.
* **Tokenization vs. Encryption Comparison:**
* *Advantages of Tokenization:* Eliminates PCI-DSS and sensitive financial database scope entirely; tokens are mathematically useless if stolen.
* *Disadvantages of Tokenization:* Requires maintaining a highly available, secure external vault architecture with real-time lookup latency.
* *Advantages of Encryption:* Self-contained (no external vault dependency).
* *Disadvantages of Encryption:* Requires managing widespread decryption keys across processing applications, expanding the risk surface.

### Part 3: Data Masking Examples

| Data Field | Full Value | Nurse (clinical) | Billing Clerk | Reception |
| --- | --- | --- | --- | --- |
| **SSN** | `987-65-4321` | `***-**-4321` | `***-**-4321` | `***-**-4321` |
| **Patient Name** | `Maria Gonzalez` | `Maria Gonzalez` | `Maria Gonzalez` | `Maria Gonzalez` |
| **Diagnosis** | `Type 2 Diabetes` | `Type 2 Diabetes` | `Restricted / Hidden` | `Restricted / Hidden` |

* **SSN Masking Justification:** All roles see only the last four digits (`***-**-4321`) because non-clinical and administrative staff have no operational need to view full government identifiers, enforcing strict data minimization.
* **Patient Name Justification:** All three operational roles require the full patient name (`Maria Gonzalez`) to correctly identify, schedule, and route patients through physical and financial hospital workflows.
* **Diagnosis Justification:** Nurses retain full clinical visibility into diagnoses to deliver proper bedside care, whereas billing clerks and receptionists are restricted from viewing protected health condition data under HIPAA minimum-necessary rules.

### Part 4: Steganography as Threat Vector

Steganography poses a severe, stealthy threat to MedDefense’s data loss prevention (DLP) program because it weaponizes routine operational workflows. Large binary medical assets, such as DICOM MRI and CT imaging files (`pacs-srv-01`), routinely traverse internal and external networks between Central Hospital and Westside Clinic, providing massive cover media capacity. A malicious insider or compromised workstation can easily modify least-significant bits (LSB) within legitimate DICOM image headers or pixel arrays to embed thousands of compressed patient records without altering the visual appearance or file size profile of the medical scan.

Traditional signature-based network monitoring and content inspection tools struggle to flag these files because the carrier traffic appears entirely benign and authorized. To effectively counter this threat vector, MedDefense must rely on continuous egress anomaly detection, endpoint behavioral monitoring, and strict internal micro-segmentation (**CIS Control / NIST Protect function** implemented via our 1x03 strategy) to prevent unauthorized data staging and restrict direct outbound connections from high-value clinical imaging repositories.
