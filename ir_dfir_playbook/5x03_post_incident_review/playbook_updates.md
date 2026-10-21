# Playbook Updates: IR-2026-0414-01

Playbook under review: `5x00_incident_response/playbook_credential_exposure.yaml` (PB-001). Gap IDs refer to [gap_analysis.md](gap_analysis.md). Finding references point to [control_effectiveness.yaml](control_effectiveness.yaml) and [forensic_findings_summary.md](5x03/forensic_findings_summary.md).

### Change PB-UPD-001

**Playbook:** playbook_credential_exposure.yaml
**Section:** applies_to.triggers (and applies_to.indicators)
**Gap closed:** GAP-004 (no geo/IP block for 45.63.9.88), GAP-005 (risk signals not routed to SOC)
**Finding reference:** control_effectiveness.yaml phase 2; forensic summary open item (session origin 45.63.9.88, RU)

**Before (triggers, abbreviated):**
```yaml
triggers:
  - Splunk or Azure AD Identity Protection alert - successful sign-in from a foreign IP or country new to the user, confirmed not the user
```
**Before (indicators, abbreviated):**
```yaml
indicators:
  - VPN login or Epic access under the user's ID from an unusual IP, workstation or patient set
```

**After:**
```yaml
triggers:
  - Splunk or Azure AD Identity Protection alert - successful sign-in from a foreign IP or country new to the user, confirmed not the user
  - VPN authentication from a country not seen for this account in the prior 30 days
  - Impossible-travel on the account (two successful logins from geographically inconsistent IPs within 2 hours)
indicators:
  - VPN login or Epic access under the user's ID from an unusual IP, workstation or patient set
```

**Reason:** The Azure AD foreign-IP trigger already exists, but VPN logins appear only as an indicator. A VPN login from a new country or an impossible-travel pair therefore starts no playbook by itself. In the incident, the first foreign session (2026-04-13T18:14:41Z) and the containment (2026-04-14T03:58Z) were about 9.7 hours apart, so the playbook would have had nine hours of activation delay.

---

### Change PB-UPD-002

**Playbook:** playbook_credential_exposure.yaml
**Section:** containment_actions (new step after "Decide containment timing")
**Gap closed:** GAP-014 (workstation-to-workstation C$ writes allowed), GAP-016 (LIS-WSIDE-01 never isolated)
**Finding reference:** forensic summary ART-003-M01 (WST-WS-017 logon via Kerberos from WST-WS-031); AD-LOG-01; incident_sysmon.jsonl EID 1 at 03:43:30Z

**Before (abbreviated):**
```yaml
containment_actions:
  - step: Decide containment timing - reset immediately or monitor briefly
    ...
  - step: Reset Active Directory password
```
The playbook has no step for expanding containment to hosts reached from the compromised account.

**After (new step inserted between the two):**
```yaml
  - step: Scope expansion checklist - run when any lateral movement indicator appears
    owner: Technical_Lead
    decision_point: >-
      Triggers: a type 3 or type 10 logon by the compromised account from one workstation to another
      (4624), an admin-share path in a process command line (for example \\host\C$), or bulk file reads
      from a share (4663). For each host found:
      1. Isolate the host and capture memory before any reboot.
      2. Pull 4624 logons for the account from the exposure-window start to now and list the source host of each.
      3. Check the source host's lsass and recent processes for the same account.
      4. Add each new host to the evidence list and repeat steps 1 to 3.
      Stop when one full hunt pass finds no new host.
    trade_off: Finds the full blast radius but isolates clinical workstations, which can interrupt care. Use the charge nurse call from the Epic step first.
```

**Reason:** The incident spread from WST-WS-031 to WST-WS-017 and LIS-WSIDE-01 before any host was isolated, and LIS-WSIDE-01 was never isolated at all. The playbook had no structured way to find those hosts.

---

### Change PB-UPD-003

**Playbook:** playbook_credential_exposure.yaml
**Section:** containment_actions (new step after "Reset Active Directory password")
**Gap closed:** GAP-011 (no LSASS access telemetry while NTLM material was in memory), GAP-012 (Credential Guard and RunAsPPL not enforced), GAP-013 (Kerberos type 3 logon not flagged)
**Finding reference:** forensic summary ART-003-M01 (MSBuild launched via Kerberos logon, T1550.003); ART-002-M04 (NTLM hash material for dmarsh in lsass)

**Before (abbreviated):**
```yaml
  - step: Reset Active Directory password
    owner: Technical_Lead
    decision_point: Only after evidence is captured. Force an Azure AD Connect delta sync afterwards
    trade_off: Invalidates the stolen password for AD, Epic and VPN, but not open sessions or issued tokens, so steps 3 to 6 follow at once. ...
```
The original text resets only the user's password. It does not invalidate Kerberos tickets already issued to an attacker.

**After (new step following the password reset):**
```yaml
  - step: Kerberos ticket invalidation - krbtgt double reset, mandatory when Pass-the-Ticket is confirmed
    owner: Technical_Lead
    decision_point: >-
      Mandatory when Kerberos ticket theft is confirmed (4624 logon type 3 from a non-server source with
      an attacker-controlled account, or a 4769 request for a ticket the user did not make). Reset krbtgt
      once, wait at least 10 hours (the default TGT lifetime) and confirm replication with repadmin
      /showrepl on every domain controller, then reset it a second time. Do not skip the wait.
    trade_off: Invalidates TGTs signed with the old key, including stolen ones, but breaks service accounts and sessions across the domain and needs a planned change window. Record the impact in the decision log.
```

**Reason:** The incident used a stolen Kerberos logon to reach WST-WS-017, so a password reset alone leaves valid TGTs usable until they expire. Note that the summary records no evidence of forged (golden) tickets. The double reset is justified by the stolen-ticket path, not by forgery.

### Change PB-UPD-004

**Playbook:** playbook_credential_exposure.yaml
**Section:** escalation_triggers (new decision node under the existing HIPAA trigger)
**Gap closed:** GAP-015 (14 PHI reads with no alert), GAP-017 (no DLP stop, exfiltration not ruled out)
**Finding reference:** forensic summary AD-LOG-01 (14 PDF reads, LIS_REPORTS$, 03:43:30Z); open item (DLP review outside this engagement)

**Before (abbreviated):**
```yaml
escalation_triggers:
  - >-
    HIPAA assessment trigger - was ePHI accessible from the compromised account during the exposure
    window ... If yes or unknown, notify the Legal_Liaison within 60 minutes and start the breach risk
    assessment from the Epic audit patient list. The Legal_Liaison sets HIPAA, Oregon and Washington deadlines
```
The playbook starts a breach risk assessment but does not say what it must cover, so it has no four-factor decision node for clinical systems.

**After (new decision node):**
```yaml
escalation_triggers:
  - >-
    HIPAA assessment trigger (unchanged text above)
  - >-
    Decision node hipaa_four_factor_assessment - runs when any ePHI system is in the blast radius
    (Epic, LIS, Nexus Patient Scheduling, or a report share). Document all four factors, from the Epic
    audit and the file-access logs:
    1. Nature and extent of PHI: data types, identifiers, and the number of patients.
    2. Unauthorized person: who accessed it, and whether they are known.
    3. Whether PHI was actually acquired or viewed: the file-read and download logs.
    4. Extent of mitigation: containment actions taken and whether the data was retrieved or destroyed.
    If the assessment cannot show a low probability of compromise, the Legal_Liaison treats it as a
    breach and sets the notification deadlines.
```

**Reason:** The 14 PHI reads are confirmed in AD-LOG-01, so factor 3 is already answered. Exfiltration is not ruled out, so factor 4 stays open until the DLP review is complete. Without a decision node, the assessment could skip any factor.

## Items to resolve before applying

- **The playbook file was not edited.** The change entries above are documented only. The playbook is a shared IR procedure in `5x00_incident_response`, so applying these changes needs your approval and the playbook owner's review.
- **The brief's example does not match the playbook.** The brief's example "Before" (`Alert: credential submitted to external domain`) does not exist in the file. The real trigger text is quoted above. Its "Gap closed: GAP-002" is the mail gateway gap, not the VPN gap, so PB-UPD-001 uses GAP-004 and GAP-005 instead.
- **The brief's premise is partly wrong.** The playbook already has an Azure AD foreign-IP trigger and a HIPAA escalation trigger. The real gaps are the missing VPN-specific and impossible-travel triggers, the missing scope expansion, the missing krbtgt reset, and the missing four-factor node.
- **The brief's time figure is wrong.** "Over eight hours" understates the gap. The timeline gives about 9.7 hours from the first foreign session (18:14:41Z) to containment (03:58Z).
