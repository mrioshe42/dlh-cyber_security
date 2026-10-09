# MedDefense Severity Matrix

## Purpose

Common severity language for all MedDefense incidents, from the Tier 1 analyst to the CISO and General Counsel. Applied from first alert through closure.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|---|---|---|---|---|---|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

An incident takes the level of its **highest** criterion. One SEV1 value is enough to make it SEV1.

## Level Definitions

### SEV1

- Ransomware encrypting Epic or LIS-WSIDE-01 across Main Hospital and other sites
- Confirmed exfiltration of patient records at scale (a large share of the ~180,000 active records)
- Epic unavailable at Main Hospital (ICU, ED, OR) during active care, with downtime past the 4-hour RTO

### SEV2

- Confirmed compromise of a clinical-access account (Epic or AD) with evidence of record access
- Malware confirmed on a single clinical workstation at West Campus, Main Hospital, or North Site
- Suspected exfiltration of patient data under investigation, or a confirmed breach at a BAA vendor such as Nexus Patient Scheduling

### SEV3

- Credential phishing click or MFA push-fatigue attempt against a clinical user, with no confirmed compromise
- Wazuh EDR alert on a clinical workstation pending triage, with no malicious execution confirmed
- Degraded LIS or Epic performance with a suspected, unconfirmed security cause

### SEV4

- Blocked commodity malware or spam caught by endpoint or email controls, with no execution
- Failed external login or port-scan noise against perimeter systems, no access gained
- Policy violation with no data or service impact (unapproved software, USB policy breach)

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval. For SEV1 and SEV2, the CISO and General Counsel are notified at the first status update after declaration, so HIPAA breach-notification clocks are tracked from the start.
