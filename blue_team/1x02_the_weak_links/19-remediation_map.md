# 19. The Remediation Map

#### Finding 031: Ghostcat (Apache Tomcat RCE)

* **Response Type:** Patch
* **Patch Source:** Apache Tomcat (Official Security Advisory).
* **Prerequisites:** Clone web-srv-01 to a staging environment, run full vulnerability scan post-patch, schedule 2-hour maintenance window.
* **Rollback Plan:** Restore pre-patch VM snapshot; revert Tomcat configuration files.
* **Operational Risk:** Incompatibility between the updated Tomcat version and legacy JSP pages.
* **Timeline:** Immediate (24-48h).
* **Owner:** IT.
* **Cost Estimate:** $0-1K (Labor).

#### Finding 003: SQL Injection (Billing Database)

* **Response Type:** Patch
* **Patch Source:** Application code remediation (input sanitization) / WAF rule update.
* **Prerequisites:** Database backup, staging environment testing, clinical audit of billing reconciliation.
* **Rollback Plan:** Revert code release; restore DB to point-in-time state.
* **Operational Risk:** Breaking billing reconciliation and patient discharge processing.
* **Timeline:** 30 days.
* **Owner:** IT / Development.
* **Cost Estimate:** $10-50K.

#### Finding 007: LDAP Relay (Active Directory)

* **Response Type:** Configuration Change
* **Change Description:** Enable "LDAP Signing" and "LDAP Channel Binding" via Group Policy.
* **Impact Assessment:** Critical. Legacy medical applications that do not support signing will break immediately upon enforcement.
* **Timeline:** 90 days (Requires 60 days of audit mode to identify legacy devices).
* **Owner:** Security / IT.
* **Cost Estimate:** $1-10K.

#### Finding 010: Alaris Pump Security (Firmware/Session)

* **Response Type:** Compensating Control
* **Control Description:** Network Micro-segmentation. Move pumps to a dedicated VLAN with strict ACLs denying all traffic except to/from the Systems Manager.
* **Residual Risk:** Risk remains within the isolated VLAN if the Systems Manager itself is compromised.
* **Timeline:** 30 days.
* **Owner:** Security / Clinical Engineering.
* **Cost Estimate:** $10-50K.

#### Finding 016: Philips IntelliVue (Unauth Port)

* **Response Type:** Compensating Control
* **Control Description:** Firewall rules restricting HL7 and web traffic to IP-specific traffic between the monitor and PIC iX server.
* **Residual Risk:** Unauthorized access remains possible if an attacker gains control of the specific IP authorized in the rule.
* **Timeline:** 30 days.
* **Owner:** IT / Clinical Engineering.
* **Cost Estimate:** $1-10K.

#### Finding 027: Billing Agent Inactive

* **Response Type:** Configuration Change
* **Change Description:** Full uninstall and clean re-install of the EDR/Security agent.
* **Impact Assessment:** Minor potential for temporary OS lockup during agent installation.
* **Timeline:** 7 days.
* **Owner:** Security.
* **Cost Estimate:** $1-10K.

#### Finding 024: IoT Gateway Management Portal

* **Response Type:** Configuration Change
* **Change Description:** Disable unauthenticated management access; enforce MFA for all administrative sessions.
* **Impact Assessment:** Operational impact on administration; requires IT staff to use MFA tokens.
* **Timeline:** 7 days.
* **Owner:** IT.
* **Cost Estimate:** $0-1K.

#### Finding 004: MRI Workstation (Windows XP)

* **Response Type:** Exception (Compensating Control)
* **Justification:** System is proprietary; cannot be patched or upgraded without replacing the entire MRI scanner ($500K+).
* **Review Date:** 6 months.
* **Monitoring:** Continuous FIM (File Integrity Monitoring) on core OS files and isolated VLAN traffic monitoring.
* **Timeline:** Immediate (Maintain current).
* **Owner:** Clinical Engineering / Security.
* **Cost Estimate:** $1-10K (Operational overhead).

### Remediation Strategy Summary

This plan prioritizes "Patching" for internet-facing vulnerabilities (Ghostcat, SQLi) where the risk of exploitation is highest. For clinical assets where stability is paramount, we have prioritized "Compensating Controls" (Segmentation/ACLs) over patching, acknowledging that these devices are inherently unpatchable. This strategy shifts MedDefense from a fragile "patch-everything" posture to a resilient, risk-based defensive architecture.
