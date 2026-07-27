## 13. The Encryption Levels

### Encryption Levels Comparison Table

| Level | Scope | Performance Impact | Key Management | Use Case |
| --- | --- | --- | --- | --- |
| **Full-disk** | Entire physical or virtual storage device (e.g., all sectors and partitions). | Minimal to low (hardware-accelerated via AES-NI or self-encrypting drives). | Centralized or single-device pre-boot authentication key. | **Best Choice When:** Securing physical hardware assets (such as employee laptops or mobile workstations) against physical theft or drive extraction. |
| **Partition** | A single logical partition or slice of a storage drive. | Minimal (operates at the block device layer, similar to full-disk). | Managed via local key files, passphrases, or integrated volume tools. | **Best Choice When:** Isolating specific operating system installation directories or scratch spaces from shared physical disks. |
| **Volume** | A logical volume manager container (which may span across multiple physical disks or arrays). | Low to moderate (transparent block-level encryption managed via device mapper). | Managed via storage controller or OS-level key stores (e.g., LUKS, BitLocker). | **Best Choice When:** Protecting multi-disk storage arrays, NAS volumes, or network-attached storage pools against unauthorized physical media access. |
| **File** | Individual files or specific directory paths within a filesystem. | Moderate (overhead scales with the number of discrete file open/write operations). | Granular user-specific keys or application-managed keychains. | **Best Choice When:** Protecting isolated sensitive documents or configuration files that require individual sharing or selective protection. |
| **Database** | Entire database instance, tablespace, or transparent data encryption (TDE) container. | Low to moderate (handled transparently by the database query engine). | Managed centrally by the database management system (DBMS) master key hierarchy. | **Best Choice When:** Securing structured database backend storage files at rest without modifying application-level database queries. |
| **Record** | Individual rows, cells, or specific sensitive columns within a database table. | High (significant computational and indexing overhead due to fine-grained cryptographic operations). | Highly complex application-layer key management mapped to individual user access levels. | **Best Choice When:** Protecting hyper-sensitive specific data elements (such as credit card primary account numbers or medical identifiers) against database administrators. |

### MedDefense Encryption Level Map

To lock down MedDefense's data stores while preserving 24/7 clinical usability, the following data-specific encryption levels are assigned, explicitly incorporating partition-level management for dedicated OS slices:

1. **Patient records in PostgreSQL (`ehr-db-01`)**

* *Recommended Level:* **Database-level (Transparent Data Encryption - TDE)**.
* *Justification:* Secures underlying database data files on disk against unauthorized physical extraction while allowing backend application queries to execute without modifying core clinical application code.

2. **Backup data on `NAS-01**`

* *Recommended Level:* **Volume-level (LUKS2)**.
* *Justification:* Encrypts massive multi-terabyte backup archives uniformly at the block storage layer to prevent data exposure if backup appliance hardware is stolen or accessed via network flaws.

3. **Financial records in MySQL (`billing-srv-01`)**

* *Recommended Level:* **Record-level (or Column-level)** for specific cardholder elements combined with Database TDE.
* *Justification:* Isolates high-risk financial payment details at the most granular level to ensure compliance with strict security thresholds and minimize broad financial exposure.

4. **Medical images on PACS (`pacs-srv-01`)**

* *Recommended Level:* **Volume-level / File-level encryption**.
* *Justification:* Secures large DICOM image file repositories stored across PACS storage tiers while maintaining high-speed read/write performance for radiology workstations.

5. **Email data in O365**

* *Recommended Level:* **Cloud Service Provider-managed File/Message-level (Microsoft Purview Message Encryption / BitLocker backend)**.
* *Justification:* Protects email communications and attachments containing protected health information natively in transit and at rest across cloud mailboxes.

6. **Employee laptops**

* *Recommended Level:* **Full-disk encryption (BitLocker / LUKS)**.
* *Justification:* Mandates complete hardware-level encryption to secure local operational data if mobile administrative or clinical laptops are lost or physically stolen.

7. **BD Alaris pump firmware/configuration**

* *Recommended Level:* **Partition-level and File-level (Isolated system partitions and signed firmware containers)**.
* *Justification:* Isolates local device scratch spaces via partition-level controls while ensuring that device configuration files and firmware payloads are integrity-protected and cryptographically verified against tampering.
