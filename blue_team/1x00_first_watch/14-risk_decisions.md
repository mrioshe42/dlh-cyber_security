# 14: The Risk Decisions

## Gap 1

**Gap ID:** GAP-001
**Gap Title:** No Network Segmentation for Medical IoT
**Risk Level:** Critical

**Treatment Strategy:** **Mitigate**

**Justification:** Network segmentation reduces lateral movement between user devices and medical equipment. The cost is low compared to the potential impact on patient safety.

* **Proposed Control(s):** Create separate VLANs for medical devices, restrict inter-VLAN traffic with firewall rules, and allow only required communication with clinical systems.
* **Estimated Cost:** **$5–10K**
* **Implementation Effort:** **Short-term (<1 month)**
* **Expected Risk Reduction:** Reduces the likelihood of malware spreading to critical medical devices and lowers the risk from **Critical** to **High**.
* **Trade-offs:** Requires network changes and scheduled testing to avoid service disruption.

## Gap 2

**Gap ID:** GAP-002
**Gap Title:** No SIEM / Network Detection
**Risk Level:** Critical

**Treatment Strategy:** **Mitigate**

**Justification:** Continuous monitoring is essential to detect attacks quickly. Although expensive, it provides the greatest overall reduction in organizational risk.

* **Proposed Control(s):** Deploy a SIEM solution, centralize log collection, and configure security alerts.
* **Estimated Cost:** **$50–80K**
* **Implementation Effort:** **Long-term (>1 month)**
* **Expected Risk Reduction:** Significantly improves threat detection and incident response across the environment.
* **Trade-offs:** High implementation and ongoing operational costs.

## Gap 3

**Gap ID:** GAP-006
**Gap Title:** No Incident Response Plan
**Risk Level:** High

**Treatment Strategy:** **Mitigate**

**Justification:** A documented response process minimizes downtime and supports HIPAA compliance at a relatively low cost.

* **Proposed Control(s):** Develop an Incident Response Plan with defined roles, escalation procedures, breach notification, and regular staff training.
* **Estimated Cost:** **$10–15K**
* **Implementation Effort:** **Short-term (<1 month)**
* **Expected Risk Reduction:** Faster containment and recovery reduce the impact of future security incidents.
* **Trade-offs:** Requires ongoing testing and employee participation.

## Gap 4

**Gap ID:** GAP-007
**Gap Title:** No Business Continuity / Disaster Recovery Plan
**Risk Level:** High

**Treatment Strategy:** **Mitigate**

**Justification:** A BCP/DRP reduces operational downtime and supports healthcare service continuity after major disruptions.

* **Proposed Control(s):** Develop documented recovery procedures, backup validation, failover testing, and clinical contingency plans.
* **Estimated Cost:** **$20–30K**
* **Implementation Effort:** **Long-term (>1 month)**
* **Expected Risk Reduction:** Reduces recovery time and limits financial and operational losses.
* **Trade-offs:** Requires planning, testing, and staff involvement.

## Gap 5

**Gap ID:** GAP-003
**Gap Title:** No Database Encryption at Rest
**Risk Level:** High

**Treatment Strategy:** **Mitigate**

**Justification:** Encryption protects sensitive patient data if servers or backups are compromised and can be implemented at a moderate cost.

* **Proposed Control(s):** Enable database encryption, encrypt backups, and implement secure key management.
* **Estimated Cost:** **$10–15K**
* **Implementation Effort:** **Short-term (<1 month)**
* **Expected Risk Reduction:** Prevents unauthorized access to stored patient information.
* **Trade-offs:** Minor performance impact and additional key management requirements.

## Gap 6

**Gap ID:** GAP-005
**Gap Title:** No Physical Access Audit Trail
**Risk Level:** High

**Treatment Strategy:** **Mitigate**

**Justification:** Monitoring physical access protects critical infrastructure and improves accountability.

* **Proposed Control(s):** Install badge access logging, visitor logs, and security cameras for server rooms.
* **Estimated Cost:** **$15–20K**
* **Implementation Effort:** **Short-term (<1 month)**
* **Expected Risk Reduction:** Detects and deters unauthorized physical access.
* **Trade-offs:** Hardware costs and ongoing monitoring responsibilities.

## Gap 7

**Gap ID:** GAP-008
**Gap Title:** Weak Endpoint Controls
**Risk Level:** High

**Treatment Strategy:** **Mitigate**

**Justification:** Endpoints are a primary attack vector. EDR improves detection and containment of ransomware and malware.

* **Proposed Control(s):** Deploy an Endpoint Detection and Response (EDR) solution and integrate alerts with the SIEM.
* **Estimated Cost:** **$25–35K**
* **Implementation Effort:** **Long-term (>1 month)**
* **Expected Risk Reduction:** Detects malicious activity quickly and limits the spread of attacks.
* **Trade-offs:** Requires ongoing management and endpoint compatibility testing.

# Budget Summary

| Gap     | Estimated Cost | Decision        |
| ------- | -------------- | --------------- |
| GAP-001 | $5–10K         | Fund in Year 1  |
| GAP-002 | $50–80K        | Fund in Year 1  |
| GAP-006 | $10–15K        | Fund in Year 1  |
| GAP-007 | $20–30K        | Defer to Year 2 |
| GAP-003 | $10–15K        | Defer to Year 2 |
| GAP-005 | $15–20K        | Defer to Year 2 |
| GAP-008 | $25–35K        | Fund in Year 1  |

**Budget Decision:** The total estimated cost exceeds the **$120K** annual budget. Year 1 funding should prioritize **SIEM, EDR, Incident Response, and Medical IoT segmentation**, providing the greatest reduction in cybersecurity risk while remaining within budget. **Database encryption, physical access upgrades, and the Business Continuity/Disaster Recovery program** should be deferred to the next fiscal year because they provide lower immediate risk reduction than detection and response capabilities.
