## 18. The Data Classification Matrix

### Part 1: Data Type Inventory

MedDefense categorizes its institutional information into six primary data types, many of which overlap across clinical and administrative systems:

1. **Regulated (HIPAA / PHI):** Patient health records, medical diagnoses, treatment notes, laboratory results, and DICOM medical imaging stored in `ehr-db-01` and `pacs-srv-01`.
2. **PII (Personally Identifiable Information):** Employee and patient names, Social Security Numbers, dates of birth, home addresses, and personal contact details.
3. **Financial:** Payment card primary account numbers (PAN), insurance billing codes, payroll records, and vendor financial ledgers stored in `billing-srv-01`.
4. **Intellectual Property:** Proprietary clinical treatment workflows, custom medical device calibration data, and internal R&D documents.
5. **Legal:** Compliance audit reports, HIPAA breach documentation, executed vendor contracts, and legal counsel correspondence.
6. **Operational:** Staff directories, internal shift schedules, IT network diagrams, server configuration files, and hospital cafeteria menus.

### Part 2: Classification Levels

| Level | Access Control | Required Encryption (At Rest) | Required Encryption (In Transit) | Exposure Impact |
| --- | --- | --- | --- | --- |
| **Public** | Universal (Patients, Staff, General Public) | None required | TLS 1.2 / 1.3 (for portal access) | **Zero Impact:** Information is intentionally public (e.g., visiting hours, hospital address). |
| **Internal** | Authenticated employees and authorized contractors | Standard OS-level or file-level storage encryption | TLS 1.2 / 1.3 for internal web apps | **Low Impact:** Minor internal friction or administrative inconvenience (e.g., staff directories, meeting schedules). |
| **Confidential** | Specific Department Heads, Executive Team, and authorized administrative roles | AES-256 database/volume encryption | TLS 1.3 with secure cipher suites | **Moderate Impact:** Competitive disadvantage, financial loss, or breach of non-public vendor contracts. |
| **Restricted** | Strictly on a Need-to-Know basis (Role-Based Access Control via AD) | AES-256 TDE / Hardware-backed KMS keys | TLS 1.3 with strict client certificate validation | **Catastrophic Impact:** Severe HIPAA regulatory fines, class-action litigation, patient safety risk, and permanent reputation damage. |

### Part 3: The Classification Decision Tree

MedDefense employees must follow this logical decision tree when evaluating and classifying any newly created or ingested data:

```text
Start: Does this data relate to patients or their protected health information (PHI)?
├── Yes ──► [RESTRICTED] (Apply database-level AES-256 and strict RBAC)
└── No ──► Does it contain financial records, payment card details (PAN), or legal contracts?
    ├── Yes ──► [CONFIDENTIAL] (Apply volume/column encryption and restricted access)
    └── No ──► Is it non-public internal operational information (e.g., staff schedules, IT configs)?
        ├── Yes ──► [INTERNAL] (Apply standard storage protection and internal-only ACLs)
        └── No ──► Is it explicitly intended for public consumption (e.g., visiting hours, marketing)?
            ├── Yes ──► [PUBLIC] (No special cryptographic controls required)
            └── No ──► Default to [INTERNAL] and consult the Data Owner (Department Head)

```

### Part 4: Sovereignty and Geolocation

Data sovereignty is critical for healthcare organizations because patient records are legally bound by strict jurisdictional regulations (such as HIPAA and regional privacy statutes) that dictate where data can reside and who holds legal authority over it. If MedDefense migrates backups to an AWS S3 Glacier region located in a different state or country, compliance violations can arise if foreign or out-of-state legal frameworks assert subpoena rights over stored healthcare records without proper safeguards. Furthermore, while robust AES-256 encryption protects data confidentiality in transit and at rest, **encryption alone does not mitigate sovereignty concerns**, as regulatory compliance mandates strict control over data locality, legal access jurisdiction, and binding Business Associate Agreements (BAAs) regardless of cipher strength.
