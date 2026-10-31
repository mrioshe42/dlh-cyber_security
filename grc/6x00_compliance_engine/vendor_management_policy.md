Policy number: MED-POL-2026-002 | Title: Vendor Management and Third-Party Risk
Effective: 2026-11-01 | Owner: IT Security + Procurement | Approved by: CISO

**No third party accesses MedDefense systems or data without security approval and risk tier classification.**

## Vendor Risk Tiers

**Tier A (Critical):** ePHI or clinical system access → full vetting + executed BAA required
- Backup providers, imaging vendors, Epic integrations, cloud infrastructure with ePHI

**Tier B (Standard):** Internal systems only; no ePHI → questionnaire + basic controls
- IT managed services, email, general office software

**Tier C (Low):** No system access → documented only
- Office supplies, facilities, physical vendors

## Tier A Pre-Engagement: ALL Required

1. **SOC 2 Type II or HITRUST CSF** (within 12 months) OR independent pentest (within 12 months) + remediation plan
2. **Security questionnaire** completed (encryption, IR, data retention, subprocessors, compliance)
3. **Subprocessor list:** all sub-processors disclosed with jurisdiction and data exposure scope; must be contractually bound to HIPAA safeguards
4. **Executed Business Associate Agreement** (unconditional; no access without signed BAA)

### BAA Minimum Terms
- Permitted uses and disclosures
- Safeguard obligations (HIPAA 164.312 aligned)
- **Incident notification: 24 hours of confirmed or suspected breach**
- Subprocessor flow-down obligations
- Data return or certified destruction within 30 days post-termination
- Right to audit and independent investigation
- Indemnification for vendor breaches
- Immediate access revocation on termination

### Tier B: Questionnaire + Encryption Evidence
### Tier C: Name + Vendor Registry Only

## Ongoing Management

**Annual reviews (Tier A):** Verify current SOC 2/HITRUST; confirm no material changes.

**Immediate out-of-cycle review triggered by:**
- Ownership transfer or major restructuring
- New subprocessor or data center change
- Security incident
- Non-compliance with BAA terms

Action: IT Security reviews within 30 days; escalate to CISO if Tier A at risk.


## Offboarding
- Access revoked within 24 hours
- Data destruction certified within 30 days
- Records retained 6 years (HIPAA)

## Incident Notification
- Vendor notifies within 24 hours of confirmed/suspected incident
- MedDefense conducts independent investigation
- Vendor provides forensic evidence and logs on request

## Tier A Evaluation Checklist

- [ ] SOC 2 Type II or HITRUST (≤12 months) or pentest (≤12 months) + remediation?
- [ ] Questionnaire completed?
- [ ] Pentest results reviewed; critical findings remediated?
- [ ] Subprocessor list; all jurisdictions acceptable?
- [ ] BAA drafted with all required terms + legal review?
- [ ] BAA executed before any access?
- [ ] Data classification and encryption documented?
- [ ] DR sites disclosed?
- [ ] Incident notification SLA = 24 hours?
- [ ] Data deletion SLA = 30 days max?
- [ ] Approved by IT Security + Procurement + CISO?

## Non-Compliance Consequences

- Tier A without BAA: immediate revocation + CISO escalation
- Missed 24-hour incident notification: 30-day cure or termination
- Undisclosed material change: immediate review + termination
- Breach of safeguards: investigation + 30-day termination decision

**CISO signature:** _________________ | Date: _______ | Next review: 2027-11-01
