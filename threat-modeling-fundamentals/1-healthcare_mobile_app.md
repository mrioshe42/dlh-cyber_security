# Healthcare Mobile App Threat Modeling

### System Overview

**Mobile Client:** iOS/Android | **Backend:** REST API | **Database:** Cloud-hosted | **Hospital Integration:** Legacy Systems

```
Core Features:
├─ View Medical Records (auth required)
├─ Schedule Appointments (auth required)
├─ Message Healthcare Providers (auth required) [CRITICAL]
├─ Receive Prescription Refills (auth required)
└─ Hospital System Integration (backend-to-backend)
```

---

## Q1: Most Critical Asset - CIA Triad Analysis

### Critical Asset Identification

**MOST CRITICAL ASSET: Patient Medical Records (PHI - Protected Health Information)**

### CIA Triad Justification

#### CONFIDENTIALITY - HIGH CRITICALITY

| Aspect | Details |
|--------|---------|
| **Why Critical** | Medical records contain sensitive information (diagnoses, medications, treatment history) |
| **Regulatory Requirement** | HIPAA mandates strict confidentiality controls |
| **Business Impact** | Breach = massive fines (up to $1.5M per violation) + reputation damage |
| **Threat** | Unauthorized access by competitors, malicious actors, or even other healthcare staff |
| **Example Scenario** | Attacker gains API access, downloads complete medical history of 10,000 patients |

#### INTEGRITY - HIGH CRITICALITY

| Aspect | Details |
|--------|---------|
| **Why Critical** | Incorrect medical data can lead to wrong treatment decisions |
| **Regulatory Requirement** | Patient safety is paramount (medical liability exposure) |
| **Business Impact** | Altered prescriptions = patient harm, lawsuits, criminal charges |
| **Threat** | Attacker modifies dosage, medication type, or allergies |
| **Example Scenario** | Patient record modified to remove penicillin allergy; patient receives penicillin and has severe reaction |

#### AVAILABILITY - MEDIUM-HIGH CRITICALITY

| Aspect | Details |
|--------|---------|
| **Why Critical** | Doctors need access to records for patient care decisions |
| **Regulatory Requirement** | System downtime = delayed care |
| **Business Impact** | Service unavailability = lost revenue + patient harm |
| **Threat** | DDoS attack or database failure prevents access to critical records |
| **Example Scenario** | App goes down during emergency; ER doctor cannot access patient allergies |

---

### Ranking by Criticality

| Rank | Asset | Justification |
|------|-------|---------------|
| 1st | **Patient Medical Records (PHI)** | Affects all three CIA components; HIPAA-regulated; patient safety critical |
| 2nd | Authentication Credentials | If compromised, attacker gains access to all patient data |
| 3rd | Prescription Data | Direct patient safety impact if modified |
| 4th | Appointment Schedule | Lower risk but impacts operational continuity |

---

## Q2: STRIDE Analysis - "Message Healthcare Providers" Feature

### System Flow for Messaging

```
Patient App → REST API → Message Queue → Provider App
     |              |
     └──────────────┘ Database
```

---

### STRIDE Threat #1: SPOOFING - Identity Impersonation

| Element | Details |
|---------|---------|
| **Threat Category** | SPOOFING |
| **Description** | Attacker impersonates a healthcare provider to send fraudulent medical advice |
| **Attack Scenario** | Attacker compromises provider account credentials (phishing/credential reuse); sends message claiming to be Dr. Smith authorizing unnecessary expensive treatment |
| **Potential Impact** | Patient receives incorrect medical advice; unnecessary procedures; patient harm; liability |
| **Likelihood** | MEDIUM-HIGH - depends on authentication strength |
| **Mitigation** | Implement MFA for provider accounts; Add digital signature verification on provider messages; Implement message signing with provider certificates; Log all message senders with IP/device info |

---

### STRIDE Threat #2: TAMPERING - Message Modification

| Element | Details |
|---------|---------|
| **Threat Category** | TAMPERING |
| **Description** | Attacker intercepts and modifies message content in transit or at rest |
| **Attack Scenario** | Man-in-the-middle attack: Message "Take 1 tablet daily" modified to "Take 10 tablets daily"; Attacker gains database access, changes prescription instructions |
| **Potential Impact** | Patient overdose or underdose; medical complications; patient harm; legal liability |
| **Likelihood** | MEDIUM - if encryption not enforced |
| **Mitigation** | Enforce TLS 1.2+ on all API communications; Encrypt messages at rest (AES-256); Implement message integrity checks (HMAC signatures); Use timestamp validation to detect old messages |

---

### STRIDE Threat #3: REPUDIATION - Denial of Message Sending

| Element | Details |
|---------|---------|
| **Threat Category** | REPUDIATION |
| **Description** | Provider denies sending a message that caused patient harm; no audit trail exists |
| **Attack Scenario** | Provider claims they never sent prescription advice; patient sues; no logs prove otherwise; liability falls on hospital |
| **Potential Impact** | Unable to prove provider accountability; legal disputes; patient trust erosion |
| **Likelihood** | MEDIUM - common in healthcare disputes |
| **Mitigation** | Implement comprehensive audit logging of all messages (sender, timestamp, content hash); Store immutable logs in separate secure location; Require digital signatures on critical messages (prescriptions); Implement non-repudiation through digital certificates |

---

### STRIDE Threat #4: INFORMATION DISCLOSURE - Unauthorized Data Access

| Element | Details |
|---------|---------|
| **Threat Category** | INFORMATION DISCLOSURE |
| **Description** | Attacker gains unauthorized access to message history containing sensitive medical information |
| **Attack Scenario** | Attacker exploits weak API authentication; downloads all messages for a celebrity patient; sells to tabloid; Employee with elevated privileges accesses ex-partner's messages |
| **Potential Impact** | HIPAA breach; privacy violation; patient confidentiality loss; financial penalties; reputation damage |
| **Likelihood** | MEDIUM-HIGH - attractive target for attackers |
| **Mitigation** | Implement role-based access control (RBAC) - providers only see their own messages; Encrypt message database; Use field-level encryption for sensitive content; Implement database activity monitoring and alerting |

---

### STRIDE Threat #5: ELEVATION OF PRIVILEGE - Unauthorized Access

| Element | Details |
|---------|---------|
| **Threat Category** | ELEVATION OF PRIVILEGE |
| **Description** | Patient escalates privileges to access admin functions or other patients' messages |
| **Attack Scenario** | Patient modifies API token to include "admin" role; accesses all patient messages in system; Attacker exploits JWT validation bug, forges admin token |
| **Potential Impact** | System compromise; mass data breach; regulatory violation |
| **Likelihood** | MEDIUM - common API vulnerability |
| **Mitigation** | Implement strict JWT validation (signature verification, expiration checks); Never trust client-supplied role claims; Server-side authorization checks for every API call; Use opaque session tokens instead of JWT where possible; Implement API gateway with centralized auth |

---

### STRIDE Threat #6: DENIAL OF SERVICE - Message System Unavailability

| Element | Details |
|---------|---------|
| **Threat Category** | DENIAL OF SERVICE |
| **Description** | Attacker floods message system with requests, making it unavailable for legitimate users |
| **Attack Scenario** | Attacker sends thousands of messages per second from multiple IPs; System becomes unresponsive; Patient cannot receive critical appointment reminders |
| **Potential Impact** | Service unavailability; patient care disruption; operational impact |
| **Likelihood** | MEDIUM - messaging systems are common DDoS targets |
| **Mitigation** | Implement rate limiting (per user, per IP); Use message queue with throttling; Deploy DDoS protection service; Implement request validation and CAPTCHAs; Monitor system load and auto-scale |

---

## Q3: Top Five Security Controls (Priority Order)

### Control Priority Matrix

| Priority | Control | Why First | Implementation |
|----------|---------|-----------|-----------------|
| **CRITICAL (P0)** | **1. Multi-Factor Authentication (MFA)** | Access control is first line of defense; prevents account takeover | Require MFA for all users (TOTP/SMS); mandatory for providers |
| **CRITICAL (P0)** | **2. End-to-End Encryption** | PHI in transit/at rest must be encrypted; HIPAA requirement | TLS 1.2+ for all API calls; AES-256 encryption for data at rest; client-side encryption option |
| **CRITICAL (P0)** | **3. Role-Based Access Control (RBAC)** | Enforce least privilege principle; prevent unauthorized data access | Define roles: Patient, Provider, Admin; API enforces permissions server-side; deny by default |
| **HIGH (P1)** | **4. Comprehensive Audit Logging** | Non-repudiation + forensic investigation capability | Log all PHI access (who, what, when, where); immutable logs; 7-year retention for compliance |
| **HIGH (P1)** | **5. Database Activity Monitoring (DAM)** | Detect unusual queries + insider threats | Monitor SQL queries in real-time; alert on mass data extractions; track database access patterns |

---

### Detailed Control Specifications

#### Control 1: Multi-Factor Authentication (MFA)

```
Implementation Steps:

1. Authentication Flow
   User enters: Username → Password → MFA Verification
   Provider: TOTP App (Google Authenticator) or SMS code
   
2. Session Management
   Session tokens: 15-minute expiration
   Refresh tokens: 7-day expiration
   Token storage: httpOnly, Secure cookies
   
3. Provider-Specific Requirements
   MFA mandatory (no exceptions)
   Failed attempts locked after 5 tries
   Account recovery process with identity verification

Risk Mitigation:
- Prevents unauthorized account access (even if password compromised)
- Reduces credential stuffing attacks by 99%
- HIPAA recommended practice
```

#### Control 2: End-to-End Encryption

```
Implementation Approach:

In-Transit Protection (TLS)
├─ TLS 1.2 minimum (prefer 1.3)
├─ Strong cipher suites only
├─ Certificate pinning for mobile apps
└─ HSTS headers (enforce 1 year)

At-Rest Encryption
├─ Database: AES-256 for PHI
├─ Backups: Encrypted with separate key
├─ Message Queue: Encrypted messages
└─ Logs: Encrypted if containing PHI

Optional: End-to-End (E2E)
├─ Client encrypts before API submission
├─ Server cannot read unencrypted data
├─ Only intended recipient can decrypt
└─ Ensures privacy even from healthcare staff

Compliance: HIPAA Encryption Standard 45 CFR 164.312(a)(2)(ii)
```

#### Control 3: Role-Based Access Control (RBAC)

```
Role Definitions:

Patient Role
├─ View own medical records
├─ Schedule own appointments
├─ Message own providers
├─ Cannot: View other patients' data, modify records

Provider Role
├─ View assigned patient records
├─ Send/receive messages with patients
├─ Manage own schedule
├─ Cannot: Access other providers' patients (unless authorized)

Admin Role
├─ System configuration
├─ User management
├─ Audit log access
├─ Cannot: Access PHI (separated admin account)

Implementation: Server-Side Authorization Checks
Every API endpoint MUST verify:
- User is authenticated (token valid)
- User role matches operation (e.g., Patient viewing own records)
- No client-side role manipulation possible
```

#### Control 4: Comprehensive Audit Logging

```
What to Log (PHI Access Events):

Critical Events:
├─ Login attempts (success/failure)
├─ Medical record access (who, when, what data)
├─ Message sends/receives
├─ Prescription refills
├─ Permission changes
├─ Failed authorization attempts
└─ Data exports/downloads

Log Format (Immutable):
{
  "timestamp": "2024-06-15T14:32:15Z",
  "user_id": "patient_12345",
  "action": "view_medical_record",
  "resource_id": "record_67890",
  "result": "success",
  "ip_address": "192.168.1.100",
  "device_type": "iOS",
  "status": "authorized"
}

Storage & Retention:
├─ Separate secure log storage (not main database)
├─ 7-year minimum retention (HIPAA requirement)
├─ Encryption at rest (AES-256)
├─ Read-only after initial write (immutable)
├─ Regular backup to offline storage
```

#### Control 5: Database Activity Monitoring (DAM)

```
Real-Time Monitoring:

Suspicious Query Detection:
├─ Unusually large result sets (> 1000 rows from Patient table)
├─ Bulk operations (DELETE without WHERE clause)
├─ Queries accessing unauthorized tables
├─ Multiple failed auth attempts from same IP
└─ Off-hours database access

Alerting Rules:
If (query_type = "SELECT" AND rows_returned > 10000):
  -> Alert security team immediately

If (user_role = "patient" AND query = "SELECT * FROM providers"):
  -> Block query + log suspicious activity

If (database_connection_IP NOT IN approved_list):
  -> Alert + disable connection

Forensic Capabilities:
├─ Query history (6 months minimum)
├─ User behavior baseline
├─ Anomaly detection (machine learning)
├─ Insider threat identification
└─ Post-breach investigation support
```
