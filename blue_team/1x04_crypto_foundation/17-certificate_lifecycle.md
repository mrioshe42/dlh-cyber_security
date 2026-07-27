## 17. Certificate Lifecycle Management

### Certificate Inventory

| Certificate Name / Purpose | Target Asset | Current Issuer | Estimated Expiration Date | Responsible Owner |
| --- | --- | --- | --- | --- |
| **Patient Portal Public TLS** | `web-srv-01` | Commercial CA (Untracked / Legacy) | **18 Days (Critical Alert)** | **IT Director (Sarah Park)** |
| **Internal EHR Transport TLS** | `ehr-srv-01` / `ehr-db-01` | Self-Signed / Internal Default | Expired / Untracked | **IT Director (Sarah Park)** |
| **VPN Gateway Authentication** | Firewall / VPN Gateway | Corporate Self-Signed CA | 45 Days | **IT Director (Sarah Park)** |
| **Email Encryption & Signing** | Microsoft O365 / Exchange | Commercial Managed CA | 180 Days | **Deputy CISO (James Chen)** |
| **Medical Device Code Signing** | BD Alaris / IoT Systems | Legacy Vendor Root CA | 1 Year | **Biomedical Engineering Lead** |


### Auto-Renewal Strategy

* **Recommendation:** MedDefense will adopt the **ACME Protocol (via Let's Encrypt or automated internal CA integration)** for all public-facing and standard internal web services (such as the patient portal `web-srv-01`), supplemented by an internal automated Microsoft Certificate Services / Vault PKI for internal server-to-server assets.
* **Justification for the Patient Portal:**
* With an average of 800 daily patient portal visits, an unexpected certificate expiration triggers an immediate browser security hard-block (*"Your connection is not private"*). This instantly erodes patient trust, blocks critical appointment and record-access workflows, and floods the clinical helpdesk with emergency calls.
* Manual commercial certificate tracking has already proven prone to human error (as evidenced by the current 18-day emergency). Shifting to automated ACME validation eliminates manual oversight, accommodates modern industry trends toward shortened cryptographic lifespans, and guarantees zero-downtime rolling renewals without human intervention.

### Monitoring and Alerting

* **Monitoring System:** Integrated into the enterprise SIEM (**Wazuh**) and automated certificate tracking daemons scanning internal and perimeter endpoints daily.
* **Threshold-Based Alerting Matrix:**
* **90 Days Out (Info):** Automated log event recorded in the SIEM for inventory tracking.
* **60 Days Out (Low Notice):** Automated ticket generated for the IT operations queue.
* **30 Days Out (Medium Warning):** Email alert dispatched to **IT Director (Sarah Park)** and the **Security Analyst** to verify automated renewal pipelines.
* **7 Days Out (High Escalation):** Urgent paging alert sent directly to **Sarah Park** and **Deputy CISO (James Chen)** if the automated renewal handshake has not successfully updated the active keystore.

### Certificate Policy (5 Rules)

1. **Rule 1: Prohibition of Self-Signed Certificates in Production**
* *All production systems, external portals, and internal medical applications must use certificates issued by a trusted public CA or MedDefense’s internal Enterprise CA. Self-signed certificates are strictly prohibited in production environments.*


2. **Rule 2: Mandatory Automation for Public Endpoints**
* *All external-facing web services and portals must utilize automated lifecycle management (e.g., ACME protocol) to execute rolling renewals well in advance of expiration, eliminating manual scheduling dependencies.*


3. **Rule 3: Cryptographic Algorithm Standards**
* *Legacy hashing algorithms (MD5, SHA-1) and weak key lengths (RSA under 2048-bit) are banned. All new certificates must utilize RSA-3072+ or ECDSA (P-256/P-384) paired with SHA-256 or higher signature verification.*


4. **Rule 4: Centralized Inventory Tracking**
* *No certificate may be deployed independently or outside of the central tracking inventory. Any shadow or unrecorded certificate discovered during regular scans will be subject to immediate administrative review and revocation.*


5. **Rule 5: Immediate Revocation and Replacement on Compromise**
* *If a private key is suspected or confirmed to be exposed, compromised, or associated with an infrastructure security breach, the affected certificate must be manually revoked within 24 hours and replaced with a newly generated key pair.*
