# 23. The Validation Plan

### 1. Post-Patch Verification (Immediate Remediations)

We will verify the top three critical remediations to ensure the vulnerabilities are truly closed and not just "hidden."

| Finding | Remediation Action | Verification Methodology |
| --- | --- | --- |
| **031 (Ghostcat)** | Update/Disable AJP Connector | **Version Check + Port Probe:** Scan the service to confirm version update. Attempt connection to the AJP port (8009) to ensure it is closed/refusing connections. |
| **007 (LDAP Relay)** | Enable SMB/LDAP Signing | **NTLM Relay Test:** Use an internal security assessment tool (e.g., Responder or CrackMapExec) to attempt an NTLM relay attack against the DC. Success = Fail; Blocked = Pass. |
| **003 (Billing DB)** | Patch Database Service | **Credentialed Scan:** Perform a credentialed scan using the vulnerability scanner to ensure the specific CVE identifier is no longer detected in the application/database version output. |

### 2. Compensating Control Validation

Because legacy systems like the MRI and IoT cannot be patched, we must treat their compensating controls as "living" security assets.

* **MRI Workstation (VLAN Isolation):**
* **Test:** Periodic "Egress/Ingress Validation." Once a quarter, attempt to connect from a workstation on a non-clinical VLAN to the MRI IP address.
* **Success Metric:** Zero packets permitted; firewall logs must show explicit "Deny" events for the traffic.
* **Medical IoT (Default Credential Hardening):**
* **Test:** Authorized "Brute-Force Simulation." Use an internal asset manager to periodically attempt to authenticate to IoT devices using a list of known default vendor credentials.
* **Success Metric:** Zero successful logins.

### 3. Rescan Schedule

MedDefense will adopt a **bi-weekly (every 14 days) scanning frequency** for the internal network, with **monthly deep audits**.

* **Justification:** A 14-day cycle provides a balance between the speed at which threat actors weaponize new CVEs (often within 48–72 hours) and the reality of change management in a clinical environment.
* **Triggered Scans:** Any major change to the network core (firewall rule update, switch replacement) or major software deployment triggers an **ad-hoc rescan** immediately following the change.

### 4. Continuous Intelligence

We will move from reactive patching to **intelligence-led patching** by integrating external data:

1. **CISA KEV (Known Exploited Vulnerabilities) Ingestion:** Security Analysts must cross-reference the CISA KEV catalog against our asset inventory **every 24 hours**. Any asset matching a KEV entry moves to "Immediate" priority, bypassing the standard lifecycle.
2. **Vendor Advisories:** We will subscribe to vendor security mailing lists (Microsoft, Siemens, Cisco, Fortinet). Advisories are parsed by the Security Analyst and converted into tickets for IT Ops within one business day.
3. **Threat Feed Updates:** We will integrate threat intel feeds (e.g., H-ISAC) into our firewall and endpoint logs to proactively block known malicious IPs/hashes associated with active healthcare campaigns.

### 5. Lifecycle Diagram

This lifecycle ensures accountability and prevents the "silent failure" of security controls.

| Step | Action | Responsibility |
| --- | --- | --- |
| **Scan** | Execute automated network/endpoint audits. | Security Analyst |
| **Triage** | Filter False Positives; identify "Actionable" items. | Security Analyst |
| **Prioritize** | Assign risk level based on Asset Criticality & Kill Chain. | Security Analyst + Management |
| **Remediate** | Execute patches/configuration changes. | IT Ops / Vendor |
| **Validate** | Verify the fix (re-scan or manual test). | Security Analyst |
| **Repeat** | Log result and return to Scan cycle. | All |
