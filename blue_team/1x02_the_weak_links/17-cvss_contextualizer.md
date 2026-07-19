# 17. The CVSS Contextualizer

### Triage: Contextualized Risk Priorities

#### 1. Finding 031: Ghostcat (Web-srv-01)

* **CVSS Base Score:** 9.8 (Critical)
* **Factor 1 (Asset):** Clinical Portal (Critical).
* **Factor 2 (Kill Chain):** Initial Access / Remote Code Execution.
* **Factor 3 (Exploit):** 5/5 (Public exploit available).
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **9.8**
* **Final Priority:** **CRITICAL**
* **Justification:** This vulnerability provides an unauthenticated, remote attacker with full system access to a web-facing clinical portal. It is a "front door" for total network compromise.

#### 2. Finding 007: LDAP Relay (DC-01)

* **CVSS Base Score:** 8.8 (High)
* **Factor 1 (Asset):** Domain Controller (Critical).
* **Factor 2 (Kill Chain):** Lateral Movement / Privilege Escalation.
* **Factor 3 (Exploit):** 4/5 (Standard enterprise toolset).
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **9.5** (Adjusted for Asset Criticality).
* **Final Priority:** **CRITICAL**
* **Justification:** LDAP relay effectively grants the attacker Domain Admin privileges. Once the DC is controlled, the entire environment—including all clinical and billing systems—is compromised.

#### 3. Finding 010: Alaris Infusion Pump (Medical IoT)

* **CVSS Base Score:** 9.0 (Critical)
* **Factor 1 (Asset):** Infusion Pump (Life-Critical).
* **Factor 2 (Kill Chain):** Sabotage / Patient Safety.
* **Factor 3 (Exploit):** 5/5 (Trivial configuration error).
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **9.8** (Adjusted for Availability/Safety impact).
* **Final Priority:** **CRITICAL**
* **Justification:** Vulnerabilities affecting infusion pumps are not just IT risks; they are physical threats to patient safety. The ability to modify dosing controls requires zero-day remediation.

#### 4. Finding 004: MRI Workstation (Windows XP)

* **CVSS Base Score:** 9.8 (Critical)
* **Factor 1 (Asset):** MRI Scanner (Clinical/Diagnostic).
* **Factor 2 (Kill Chain):** APT Persistence / Long-term access.
* **Factor 3 (Exploit):** 4/5 (Permanent/unpatchable).
* **Factor 4 (Controls):** Partial (VLAN Isolation only).
* **Environmental CVSS:** **9.2**
* **Final Priority:** **CRITICAL**
* **Justification:** While isolated, this system is a legacy liability. It is the perfect "anchor" for an APT to maintain presence in the network indefinitely because it will never be patched.

#### 5. Finding 003: Billing Database (Billing-srv)

* **CVSS Base Score:** 8.8 (High)
* **Factor 1 (Asset):** Financial/PHI Data (Critical).
* **Factor 2 (Kill Chain):** Data Exfiltration / Objective Execution.
* **Factor 3 (Exploit):** 4/5.
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **9.0** (Adjusted for Data Sensitivity).
* **Final Priority:** **CRITICAL**
* **Justification:** This is the primary target for ransomware operators looking to steal patient data for extortion. The impact on business operations and regulatory compliance is maximal.

#### 6. Finding 016: Philips Monitor (Medical IoT)

* **CVSS Base Score:** 7.5 (High)
* **Factor 1 (Asset):** Patient Monitoring (Life-Critical).
* **Factor 2 (Kill Chain):** Espionage / Data Access.
* **Factor 3 (Exploit):** 3/5.
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **8.5** (Adjusted for Integrity/Safety requirements).
* **Final Priority:** **HIGH**
* **Justification:** Access to unauthenticated clinical data ports allows an attacker to monitor real-time patient vitals. While less severe than an infusion pump (Sabotage), it remains a high-stakes privacy and safety risk.

#### 7. Finding 024: IoT Gateway (Infrastructure)

* **CVSS Base Score:** 8.1 (High)
* **Factor 1 (Asset):** Network/IoT Core (High).
* **Factor 2 (Kill Chain):** Access / Pivot.
* **Factor 3 (Exploit):** 4/5.
* **Factor 4 (Controls):** None.
* **Environmental CVSS:** **8.1**
* **Final Priority:** **HIGH**
* **Justification:** The gateway serves as the bridge between isolated IoT devices and the main network. Compromising it bypasses existing network segmentation.

#### 8. Finding 027: Billing Agent (Endpoint)

* **CVSS Base Score:** 7.0 (High)
* **Factor 1 (Asset):** Billing Server (High).
* **Factor 2 (Kill Chain):** Persistence.
* **Factor 3 (Exploit):** 5/5 (Known disabled state).
* **Factor 4 (Controls):** Failed.
* **Environmental CVSS:** **7.8** (Adjusted for "Known Failed" state).
* **Final Priority:** **HIGH**
* **Justification:** This is a control failure, not a classic CVE. Because the EDR is inactive, the asset is currently blind to attackers. It is a "High" priority because it indicates the host is already effectively compromised.


### Priority Comparison Table

| Finding | Base CVSS | Adjusted Priority | Trend |
| --- | --- | --- | --- |
| **031** (Ghostcat) | 9.8 | **CRITICAL** | Same |
| **007** (LDAP Relay) | 8.8 | **CRITICAL** | Higher |
| **010** (Alaris Pump) | 9.0 | **CRITICAL** | Higher |
| **004** (MRI XP) | 9.8 | **CRITICAL** | Same |
| **003** (Billing DB) | 8.8 | **CRITICAL** | Higher |
| **016** (Philips) | 7.5 | **HIGH** | Higher |
| **024** (IoT Gateway) | 8.1 | **HIGH** | Same |
| **027** (Billing Agent) | 7.0 | **HIGH** | Higher |

The "Environmental Adjustment" has elevated 5 of the 8 findings. This reflects that in a clinical environment, a "High" technical vulnerability often carries "Critical" business risk when it touches patient safety or sensitive financial data. Findings 027 and 007, while not the highest raw "Base" scores, have been prioritized because of their strategic importance to the attacker's ability to maintain persistence or escalate privilege.
