## Click Investigation

### Confirmed Facts
Based on the header metadata, log notes, and evidence batch provided, the following facts are verified:

* **Target User:** Diane Marsh (`dmarsh@meddefense.com`)
* **Role / Workstation:** Nurse / `WS-NURSE-04`
* **Workstation IP Address:** `10.10.2.15`
* **Email ID:** Email 2 (E2)
* **Email Sender:** "MedDefense IT Security" `<noreply@meddefense-portal.com>`
* **Originating Sending IP:** `91.234.99.107` (PHPMailer 6.6.0 on external host)
* **Authentication Status:** SPF Fail, DKIM None, DMARC Fail
* **Email Received Timestamp:** `2026-04-14 14:47:52 -0500 (CDT)`
* **Click Timestamp:** `2026-04-14 15:02:33 CDT` (~14 minutes after delivery)
* **Target Domain:** `meddefense-portal.com`
* **Phishing URL Clicked:** `https[:]//meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`

### Key Unknowns
Because this investigation is based on the initial email batch submission without direct access to live SIEM or endpoint logs, the following critical items remain unverified:

1. **Credential Input:** Did the user enter her MedDefense domain or EHR portal credentials on the landing page after clicking the link?
2. **Session / MFA Token Interception:** Was the phishing site utilizing an Adversary-in-the-Middle (AiTM) proxy framework (e.g., Evilginx) capable of stealing active session cookies or MFA tokens?
3. **Payload Delivery:** Did the landing page attempt a secondary drive-by download, malicious browser extension installation, or exploit execution against the browser?
4. **Post-Click User Actions:** What was the user's immediate workflow after clicking (e.g., closed tab immediately upon noticing odd domain, filled out form, or reported to helpdesk)?
5. **Network Connection Duration:** What was the byte transfer size and duration of the HTTP/HTTPS session established between `10.10.2.15` and `91.234.99.107` / `meddefense-portal[.]com`?

### Risk Assessment
A confirmed click on a targeted credential-harvesting link represents a **High Severity** security incident, even if credential entry is not yet confirmed. 

1. **Role-Based Targeting & HIPAA Exposure:** As a nursing staff member operating `WS-NURSE-04`, compromised credentials could provide unauthorized access to Electronic Health Record (EHR) systems, HIPAA-regulated Protected Health Information (PHI), and internal scheduling gateways.
2. **Lookalike Pretext:** The domain `meddefense-portal[.]com` and URL structure explicitly reference `dmarsh` and include a targeted token (`a8f3e2d1`), indicating pre-crafted targeting rather than generic spam.
3. **Time Exposure / Dwell Time:** Approximately 36 hours elapsed between the reported click (`2026-04-14 15:02:33 CDT`) and evidence collection (`2026-04-17 09:15 CDT`), giving a potential adversary significant dwell time for lateral movement, mailbox persistence, or session hijacking.

### Endpoint Checks To Perform
*(Note: The following endpoint forensic checks should be executed if EDR, SIEM, or local system logs become available).*

* **Browser History & Session Storage:**
  * Inspect browser history database (`History`, `Web Data`) on Chrome/Edge/Firefox under Diane Marsh's profile for entries matching `meddefense-portal[.]com` around `2026-04-14 15:02:33 CDT`.
  * Review local storage, session storage, and cache for posted web form data or returned session tokens.
* **Downloaded Files & Artifacts:**
  * Check the user's `Downloads` directory, browser download history, and system `%TEMP%` folders for files saved on or after `15:02:33 CDT` on April 14, 2026.
* **Process Execution Logs (Sysmon / Event ID 4688):**
  * Audit process creation events originating from `msedge.exe` or `chrome.exe` around the click timestamp.
  * Search for anomalous child processes spawned by the browser (e.g., `cmd.exe`, `powershell.exe`, `wscript.exe`, `rundll32.exe`, `mshta.exe`).
* **Scripting & PowerShell Activity (Event ID 4104):**
  * Review Script Block Logging logs for any obfuscated or encoded script execution following the click.
* **File Creation & Registry Persistence:**
  * Search MFT / USN Journal for new file creations in `C:\Users\dmarsh\AppData\Local\` and `C:\ProgramData\`.
  * Inspect Registry persistence keys (`Run`, `RunOnce`, Task Scheduler tasks) for modifications.
* **Network Sockets & DNS Cache:**
  * Query local DNS cache (`ipconfig /displaydns`) and EDR network telemetry for outbound connections to `91.234.99.107` or resolved IPs for `meddefense-portal[.]com`.

### Account Checks To Perform
*(Note: The following identity and directory audits should be executed across Active Directory, Microsoft 365, and local SSO providers).*

* **Authentication & Access Logs:**
  * Audit Azure AD / Entra ID Sign-In Logs and Active Directory Event ID 4624/4625 for `dmarsh` starting from `2026-04-14 15:02:00 CDT` onward.
  * Look for anomalous source IPs, foreign geolocations, or unusual User-Agent strings.
* **MFA Prompt & Registration Telemetry:**
  * Review MFA sign-in logs for unexpected push notifications, high-frequency MFA prompts (MFA fatigue), or newly registered MFA devices (e.g., unauthorized Authenticator app additions).
* **Credential & Password Activity:**
  * Audit Active Directory Domain Controller logs (Event ID 4723 / 4724) and Azure AD audit logs for password resets or self-service password changes.
* **Exchange / Email Rule Audit:**
  * Inspect `dmarsh`'s inbox rules for newly created forwarding rules, delete/redirect rules, or hidden rules designed to suppress security notifications or billing alerts.
  * Check for changes in mailbox delegate permissions (`Add-MailboxPermission`).
* **Privilege & Group Membership Changes:**
  * Verify whether `dmarsh` was added to any administrative or sensitive AD groups during the dwell period.

### Decision Matrix

| Scenario / Outcome | Identified Criteria & Evidence | Action Required |
| :--- | :--- | :--- |
| **Outcome 1: No Compromise Found** | • Browser logs confirm URL visited, but no HTTP POST / payload submitted.<br>• Endpoint scan clean; no downloaded files or spawned processes.<br>• Identity logs show no unusual sign-ins or MFA anomalies since April 14. | • Document findings and close ticket.<br>• Provide target user with brief refresher on identifying domain spoofing.<br>• Maintain standard log monitoring for 14 days. |
| **Outcome 2: Possible Credential Exposure** | • User admits entering credentials OR network logs show HTTP POST to phishing domain.<br>• No secondary payload or malware detected on endpoint.<br>• No successful anomalous sign-ins from threat actor IPs observed. | • **Immediate Force Password Reset** across all domain and SSO systems.<br>• **Revoke Active Sessions** (e.g., `Revoke-AzureADUserAllRefreshToken`).<br>• Audit mailbox rules and MFA registered devices.<br>• Conduct 30-day targeted audit on account activity. |
| **Outcome 3: Confirmed Compromise** | • Successful sign-in detected from threat actor IP (`91.234.99.107` or secondary proxy IP).<br>• Unauthorized MFA device added OR inbox forwarding rules created.<br>• Malicious process/script executed on `WS-NURSE-04`. | • **Isolate Workstation `WS-NURSE-04`** from network.<br>• **Disable Account `dmarsh`** immediately.<br>• Initiate full SOC Incident Response (IR) triage.<br>• Preserve memory and forensic disk image of `WS-NURSE-04`.<br>• Check for lateral movement across clinical networks. |

### Recommended Containment

1. **Immediate Identity Containment:**
   * Execute an immediate password reset for user `dmarsh` across Active Directory and M365.
   * Terminate all active OAuth sessions and revoke refresh tokens (`Revoke-AzureADUserAllRefreshToken`).
   * Audit registered MFA methods under `dmarsh` to ensure no attacker device was enrolled.
2. **Workstation Isolation & Forensics:**
   * Place `WS-NURSE-04` (`10.10.2.15`) into network isolation via EDR or VLAN switch port lockdown pending forensic evaluation.
   * Run a full EDR anti-malware and rootkit scan on `WS-NURSE-04`.
3. **User Interview:**
   * Conduct a brief, non-punitive interview with Diane Marsh to establish exact actions taken after clicking the link (e.g., "Did a login page appear? Did you type your password?").
4. **Network & Perimeter Blocking:**
   * Block domain `meddefense-portal[.]com` and IP `91.234.99.107` at the perimeter firewall, web proxy, and DNS sinkhole.
5. **Account Monitoring:**
   * Place `dmarsh` on high-priority alert monitoring in SIEM for the next 30 days to flag any unusual access requests or EHR record exports.

### Conclusion
Diane Marsh’s click on Email 2 (`https[:]//meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`) represents a direct exposure to a credential-harvesting lure targeting MedDefense clinical personnel. Given the ~36-hour window since the click occurred, immediate session revocation, password reset, and endpoint isolation of `WS-NURSE-04` are necessary precautions while endpoint and identity logs are audited against the decision matrix.
