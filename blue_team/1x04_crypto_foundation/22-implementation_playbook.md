## 20. The Implementation Playbook

### Action #1: Upgrade Patient Portal TLS Configuration & Certificate

* **Priority:** Immediate (48h)
* **System Affected:** `web-srv-01`
* **Prerequisites:** Active ACME client (`certbot`) installed, administrative root access, and current DNS control verification.
* **Steps:**
1. Update Nginx configuration file (`/etc/nginx/sites-available/patient-portal`) to explicitly drop legacy protocols by modifying the `ssl_protocols` directive: `ssl_protocols TLSv1.2 TLSv1.3;`.
2. Enforce modern secure cipher suites: `ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:CHACHA20-POLY1305;`.
3. Execute the automated ACME renewal and installation script to replace the expiring certificate: `certbot --nginx -d portal.meddefense.local --force-renewal`.
4. Test syntax and reload the Nginx web service: `nginx -t && systemctl reload nginx`.
* **Validation:**
* Run `openssl s_client -connect portal.meddefense.local:443 -tls1` and confirm the server rejects the handshake. Run with `-tls1_3` and confirm successful connection.
* Verify 800 daily patient portal HTTP 200 response codes via real-time access logs and confirm zero error spikes.
* **Rollback:**
* Restore previous Nginx configuration backup: `cp /etc/nginx/sites-available/patient-portal.bak /etc/nginx/sites-available/patient-portal && systemctl reload nginx`.
* **Max Acceptable Downtime:** 5 minutes.
* **Maintenance Window:** Overnight required (Saturday, 2:00 AM – 2:30 AM).
* **Communication:** Notify IT Director Sarah Park and Helpdesk Lead prior; send completion email to Deputy CISO James Chen post-validation.

### Action #2: Enable Database Transparent Data Encryption (TDE)

* **Priority:** Phase 1
* **System Affected:** `ehr-db-01`
* **Prerequisites:** Full database backup completed and verified offline; Cloud KMS / Hardware Key Vault integration established.
* **Steps:**
1. Create the database master key on PostgreSQL/SQL backend: `CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Strong_Complex_Admin_Password_2026!';`.
2. Create a certificate protected by the master key: `CREATE CERTIFICATE EHR_TDE_Cert WITH SUBJECT = 'MedDefense EHR TDE Protection';`.
3. Create the database encryption key and encrypt the database: `CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE EHR_TDE_Cert;`.
4. Set database encryption ON: `ALTER DATABASE ehr_production SET ENCRYPTION ON;`.
* **Validation:**
* Execute state verification query: `SELECT DB_NAME(database_id) AS DatabaseName, encryption_state FROM sys.dm_database_encryption_keys;` (confirm state equals `3` for encrypted).
* Verify EHR application connectivity and query response times via test transaction scripts.
* **Rollback:**
* Turn database encryption OFF: `ALTER DATABASE ehr_production SET ENCRYPTION OFF;` and drop encryption keys if severe performance degradation occurs.
* **Max Acceptable Downtime:** 15 minutes.
* **Maintenance Window:** Overnight required (Sunday, 1:00 AM – 3:00 AM).
* **Communication:** Notify CEO, IT Director Sarah Park, and Department Heads of scheduled clinical database maintenance window.


### Action #3: Deploy Volume Encryption for Enterprise Backup Storage

* **Priority:** Phase 1
* **System Affected:** `NAS-01`
* **Prerequisites:** Storage volume unmounted or maintenance mode active; physical console or out-of-band management access verified.
* **Steps:**
1. Initialize LUKS2 encryption container on the target backup partition: `cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 /dev/sdb1`.
2. Open the encrypted volume map: `cryptsetup open /dev/sdb1 backup_secure_vol`.
3. Create the underlying filesystem: `mkfs.ext4 /dev/mapper/backup_secure_vol`.
4. Configure `/etc/crypttab` and `/etc/fstab` to utilize secure key-file mounting upon authorized system boot.
* **Validation:**
* Verify volume status: `cryptsetup status backup_secure_vol` (confirm AES-XTS 512-bit active).
* Test Veeam backup replication job execution to the newly mounted encrypted target.
* **Rollback:**
* Unmount volume, close LUKS container (`cryptsetup close backup_secure_vol`), and restore from unencrypted partition image if block mounting fails.
* **Max Acceptable Downtime:** 30 minutes.
* **Maintenance Window:** Overnight required (Saturday, 12:00 AM – 3:00 AM).
* **Communication:** Notify Infrastructure Lead and IT Director Sarah Park before and after execution.


### Action #4: Enforce Active Directory AES Kerberos Encryption

* **Priority:** Phase 1
* **System Affected:** `ad-dc-01`
* **Prerequisites:** Domain Controller audit completed to verify all legacy domain computers support AES; Group Policy Object (GPO) replication verified.
* **Steps:**
1. Open Group Policy Management on `ad-dc-01` and create/edit the domain security policy: `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
2. Configure the policy setting: `Network security: Configure encryption types allowed for Kerberos` to enable **AES128_HMAC_SHA1** and **AES256_HMAC_SHA1**, while explicitly disabling **RC4_HMAC_ELEMENT**.
3. Force immediate GPO update across all domain assets: `gpupdate /force`.
* **Validation:**
* Verify event logs on `ad-dc-01` (Event ID 4768 / 4769) to confirm service tickets are issuing AES encryption types.
* Confirm domain workstation authentication and user login success across all active subnets.
* **Rollback:**
* Modify GPO setting to re-enable RC4 compatibility mode and run `gpupdate /force` if legacy applications fail authentication.
* **Max Acceptable Downtime:** 10 minutes.
* **Maintenance Window:** Overnight required (Tuesday, 1:00 AM – 2:00 AM).
* **Communication:** Notify IT Director Sarah Park, Deputy CISO James Chen, and helpdesk support staff prior to policy push.

### Action #5: Implement Encrypted TLS Interconnects for Database Proxies

* **Priority:** Phase 2
* **System Affected:** `billing-srv-01` / `ehr-db-01`
* **Prerequisites:** Internal CA root certificate distributed to application server trust stores; database configuration files backed up.
* **Steps:**
1. Generate and sign server TLS certificates for MySQL/PostgreSQL instances via the internal Enterprise CA.
2. Update database configuration (`postgresql.conf` or `my.cnf`) to enforce secure transport: `ssl = on`, `ssl_cert_file = '/etc/ssl/certs/db_server.crt'`, `ssl_key_file = '/etc/ssl/private/db_server.key'`, and `ssl_min_protocol_version = 'TLSv1.3'`.
3. Restart database service to apply cryptographic transport requirements: `systemctl restart postgresql`.

* **Validation:**
* Verify active secure connections via CLI: `psql "host=ehr-db-01 sslmode=verify-full" -U db_admin -c "SHOW ssl;"` (confirm output is `on`).
* Verify billing and EHR application transaction logs for clean database connection handshakes.
* **Rollback:**
* Revert database configuration file (`ssl = off`) and restart service if application connection strings fail.
* **Max Acceptable Downtime:** 15 minutes.
* **Maintenance Window:** Overnight required (Sunday, 3:00 AM – 4:30 AM).
* **Communication:** Notify IT Director Sarah Park and database administrators prior to service restart.
