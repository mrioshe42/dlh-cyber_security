## 4. The Crypto Emergency

### Part 1 - Crypto Attack Surface Mapping

* **Phase 5: Lateral Movement**
* **Crypto Weakness:** `CRYPTO-006` / Unencrypted IoT device configurations and weak transport mechanisms.
* **What Crimson Tide Exploits:** The lack of cryptographic code signing and unencrypted communication channels allows attackers to pivot through medical device subnets and inject malicious control parameters into clinical devices like the Alaris Pumps.
* **Recommended Crypto Fix:** Cryptographically signed firmware containers (SHA-256 / RSA-3072) and encrypted local flash storage.
* **Emergency Timeline:** **No** (Firmware code-signing and device-level re-flashing cannot be safely accelerated within a 72-hour operational window without risking clinical device availability).

* **Phase 6: Data Exfiltration**
* **Crypto Weakness:** `CRYPTO-001` & `CRYPTO-004` / Plaintext storage files on `ehr-db-01` and unencrypted billing tables.
* **What Crimson Tide Exploits:** The complete absence of database-at-rest encryption enables threat actors who achieve database access to directly dump and exfiltrate millions of patient health and financial records without decryption hurdles.
* **Recommended Crypto Fix:** AES-256 Transparent Data Encryption (TDE).
* **Emergency Timeline:** **Partially / Conditional** (TDE activation can be rushed in an emergency window, but requires rigorous staging to avoid locking out active clinical database instances).

* **Phase 7: Impact / Ransomware Deployment**
* **Crypto Weakness:** `CRYPTO-002` / Plaintext backup storage on `NAS-01`.
* **What Crimson Tide Exploits:** Unencrypted backup repositories allow attackers to easily harvest historical institutional data for double-extortion or encrypt the backup volumes directly, destroying local recovery options.
* **Recommended Crypto Fix:** AES-256 via LUKS2 container encryption and isolated immutable cloud targets.
* **Emergency Timeline:** **Yes** (Physical disconnection of the NAS [Tier 1 72-hour action] combined with rapid deployment of an isolated LUKS2/AWS Glacier vault can be initiated immediately).

### Part 2 - Encryption Priority Re-ranking

Based on the Crimson Tide advisory and real-world attack patterns, the original 1x04 crypto priorities must be re-ranked to focus immediately on **data exfiltration prevention** and **backup protection** over long-term compliance controls.

#### Updated Crypto Priority List

1. **Priority 1 (`CRYPTO-002` - Enterprise Backup Archives):** Moved to the absolute top priority. *Reasoning:* Ransomware threat actors target backups first to eliminate recovery options. Securing backups via isolated LUKS2 encryption and immutable cloud targets is the ultimate defensive firewall against extortion.
2. **Priority 2 (`CRYPTO-001` - Patient Health Records / EHR TDE):** Elevated to immediate operational execution. *Reasoning:* Crimson Tide heavily leverages dual-extortion (data theft prior to encryption). Implementing AES-256 TDE blocks raw disk harvesting.
3. **Priority 3 (`CRYPTO-004` - Financial & Billing Records):** Retained as high priority for regulatory and PCI compliance.
4. **Priority 4 (`CRYPTO-003` - Patient Portal Web Traffic / TLS):** Adjusted to ongoing maintenance, as perimeter network blocks temporarily mitigate edge exposure.
5. **Priority 5 (`CRYPTO-005` & `CRYPTO-006` - PACS & Medical IoT):** Shifted to medium-term execution due to the high risk of clinical disruption during device-level cryptographic overhauls.

### Part 3 - The "What If" Calculation

If MedDefense's patient database (`ehr-db-01`) had been fully encrypted at rest via Transparent Data Encryption (TDE) using AES-256:

* **What would change about Phase 4/6 (Data Exfiltration)?**
If an attacker achieved basic file-system access or stole raw physical disks, the stolen database files (`.mdf`/`.db`/data directories) would appear as unreadable ciphertext, preventing immediate offline data harvesting.
* **Would the data still be exfiltrable?**
**Yes, under specific conditions.** Because the attacker has successfully attained **Domain Admin access** (Phase 3) and executed code natively on the database server, they possess the privileges required to query the running database engine directly, access memory space, or extract the active master decryption keys managed by the local OS or software keystore. Once the database instance is running and mounts the keys to serve clinical applications, an interactive attacker can export, dump, or stream the plaintext data right past the storage encryption layer. Encryption at rest protects against *static theft* (stolen hard drives or unmounted backups), but it does not automatically stop an active, privileged adversary operating live inside an already-compromised operating system.
