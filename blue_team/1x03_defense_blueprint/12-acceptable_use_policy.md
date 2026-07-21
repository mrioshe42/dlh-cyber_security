# 12. The Policy Draft

## MEDDEFENSE HEALTH SYSTEMS

### Information Security Policy: Acceptable Use Policy (AUP)

**Document ID:** POL-SEC-001

**Version:** 2.0

**Effective Date:** FY26

**Approved By:** Executive Board & Deputy CISO

**Applies To:** All employees, contractors, medical staff, volunteers, and third-party vendors accessing MedDefense Health Systems network resources, endpoints, and information assets.


### 1. Purpose and Scope

MedDefense Health Systems is committed to protecting patient health information (PHI), clinical systems, and financial assets against unauthorized access, exposure, and disruption. This Acceptable Use Policy (AUP) defines the mandatory rules and behavioral standards required of all individuals who access MedDefense information systems, corporate networks, electronic health record (EHR) systems, and remote access gateways.

This policy covers all company-owned endpoints (540 workstations and servers), mobile devices, remote clinic branches (such as Westside Clinic), and approved corporate cloud services (such as Microsoft 365). Compliance with this policy is mandatory.


### 2. Acceptable Use of Systems

MedDefense computing resources and networks are provided to support patient care, clinical research, administrative operations, and business functions.

* **Permitted Activities:** Users are permitted to access authorized clinical applications, send secure internal/external communications via official MedDefense email (`@meddefense.org`), utilize approved cloud document libraries (Microsoft Teams/SharePoint), and perform job-related web browsing.
* **Incidental Personal Use:** Limited, non-disruptive personal use of corporate workstations (e.g., checking personal email during breaks) is acceptable provided it does not interfere with work duties, consume excessive bandwidth, violate any security protocols, or involve prohibited content.

### 3. Prohibited Activities

To prevent ransomware deployment, data exfiltration, and operational disruption, the following activities are strictly forbidden:

* **Unauthorized Software & Shadow IT:** Deploying unapproved hardware (e.g., personal NAS servers, unauthorized Raspberry Pi monitors, or unmanaged routers) or signing up for unvetted cloud storage solutions (e.g., personal Google Drive accounts) on MedDefense networks is prohibited. All technology assets must be vetted and managed by IT.
* **Bypassing Security Controls:** Disabling, modifying, or attempting to circumvent endpoint protection agents (Sophos), firewalls, log forwarders, or network segmentation rules is a critical security violation.
* **Insecure Communications:** Transmitting unencrypted MedDefense PHI or sensitive financial records over unsecure public networks, personal email accounts, or unauthorized messaging apps.
* **Malicious or Unlawful Activity:** Accessing, downloading, or distributing pornographic material, engaging in unauthorized network scanning, attempting privilege escalation, or utilizing corporate systems for illegal activities.

### 4. Personal Devices and Removable Media

Uncontrolled endpoint storage and unmanaged personal hardware represent major vectors for malware introduction and data leakage.

* **Removable USB Media:** The use of unapproved, personal USB flash drives or external hard drives on MedDefense workstations is **strictly prohibited**. All USB ports on clinical and administrative workstations are locked down via Endpoint Detection and Response (EDR) policy enforcement. Approved business USB drives must be encrypted and scanned by IT prior to use.
* **Personal Laptops & Mobile Phones:** Connecting personal laptops directly to the internal MedDefense network is forbidden. Personal mobile phones may only access corporate email and resources via the official, managed Microsoft Intune Mobile Device Management (MDM) application with explicit IT enrollment.

### 5. Password and Authentication Requirements

User credentials represent the primary perimeter defense against unauthorized access to electronic health records.

* **Multi-Factor Authentication (MFA):** MFA is **mandatory** for all remote VPN connections, administrative log-ins, and Microsoft 365 access. Users must never bypass, prompt-bomb, or approve unauthorized MFA pushes.
* **Credential Confidentiality:** Passwords must be a minimum of 12 characters, complex, and unique. Sharing passwords, writing credentials on sticky notes, or utilizing shared generic accounts (such as legacy `raduser` logins) is strictly prohibited. Every user must operate solely under their own attributable credentials.

### 6. Data Handling and Classification

All data generated, processed, or stored by MedDefense must be handled in accordance with its sensitivity classification:

* **Restricted / PHI (Patient Health Information):** Includes electronic health records, patient demographic data, billing records, and social security numbers. Must be encrypted at rest and in transit. Never stored on local desktop drives, personal devices, or unmanaged cloud accounts.
* **Confidential (Internal Business Data):** Includes financial budgets, strategic plans, and proprietary research (e.g., Cardiology research data). Restricted to authorized internal personnel.
* **Public:** General press releases and marketing materials approved for public distribution.

### 7. Monitoring and Enforcement

* **Active Monitoring:** MedDefense reserves the right to monitor, log, and audit all network traffic, workstation activity, file access, and email communications across corporate assets via centralized SIEM and EDR platforms. Users should have no expectation of privacy when using corporate computing resources.
* **Violation Consequences:** Violations of this policy will result in formal disciplinary action up to and including revocation of system access, termination of employment, and potential civil or criminal legal liabilities under HIPAA and federal privacy laws.

### 8. Employee Acknowledgment and Signature Block

> *I acknowledge that I have received, read, and understand MedDefense Health Systems' Acceptable Use Policy (POL-SEC-001). I agree to abide by the terms, security controls, and data handling requirements outlined herein during my employment or association with MedDefense.*

**Employee Name (Printed):** __________________________________________________

**Department / Role:** ______________________________________________________

**Employee Signature:** ___________________________________ **Date:** ____________
