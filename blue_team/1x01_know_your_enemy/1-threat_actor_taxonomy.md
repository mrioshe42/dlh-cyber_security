# 1. The Threat Actor Taxonomy

## Report A: Pharmaceutical Drug Trial Data Theft

* **Actor Type:** Nation-state (APT group)
* **Resources:** High (custom tools, zero-day exploits).

* **Sophistication:** High (advanced persistence, custom malware).

* **Primary Motivation:** Espionage (high-value IP theft).

* **MedDefense Relevance:** Low; MedDefense lacks the cutting-edge biotech research that attracts nation-state actors.

## Report B: Hospital Ransomware via Phishing

* **Actor Type:** Organized crime / Ransomware-as-a-Service (RaaS)
* **Resources:** Medium-High (leased malware, negotiation infrastructure).

* **Sophistication:** Medium (exploits known vulnerabilities, social engineering).

* **Primary Motivation:** Financial gain (double extortion).

* **MedDefense Relevance:** CRITICAL; MedDefense matches the target profile (regional hospital). The phishing vector is highly effective, and lack of EDR (GAP-008) increases success probability.

## Report C: Hospital Website Defacement

* **Actor Type:** Hacktivist
* **Resources:** Low (freely available scanning tools).

* **Sophistication:** Low-Medium (basic SQL injection).

* **Primary Motivation:** Political/philosophical disruption.

* **MedDefense Relevance:** Low; MedDefense lacks a controversial profile, though web portal disruption remains possible.

## Report D: Malicious IT Administrator Sabotage

* **Actor Type:** Insider (malicious)
* **Resources:** Medium (legitimate access, internal knowledge).

* **Sophistication:** Medium (database dropping, backup manipulation).

* **Primary Motivation:** Revenge/sabotage.

* **MedDefense Relevance:** HIGH; MedDefense lacks automated offboarding and monitoring of administrative actions, allowing terminated employees to retain access.

## Report E: Cryptocurrency Mining

* **Actor Type:** Unskilled/Opportunistic
* **Resources:** Low (automated botnets).

* **Sophistication:** Low (exploits known CVEs).

* **Primary Motivation:** Financial (computing resource theft).

* **MedDefense Relevance:** HIGH; already confirmed by billing-srv-01 compromise. Unpatched public systems ensure continued automated scanning.

## Report F: Shadow IT Negligence

* **Actor Type:** Shadow IT (employee) / Unskilled (external exploiter)
* **Resources:** Low (personal devices, default credentials).

* **Sophistication:** Low (basic exploitation of exposed devices).

* **Motivation:** Convenience / Chaos.

* **MedDefense Relevance:** HIGH; confirmed by undocumented devices (10.10.2.99, 10.10.10.200) and lack of endpoint monitoring.

## Report G: Ambiguous Physician Account Abuse

* **Actor Type:** Unclear (Insider, Organized Crime, or Fraud Ring)
* **Motivation:** Financial (data sale/insurance fraud).

* **Confidence:** Low; requires IP tracing and fraud pattern analysis to identify the actor.

* **MedDefense Relevance:** HIGH; lack of real-time audit logs and behavioral monitoring makes this activity invisible for weeks.

## Report H: Extortion via Broken Authentication

* **Actor Type:** Organized crime / Extortionist
* **Resources:** Medium (Tor anonymity, extortion infrastructure).

* **Sophistication:** Medium (proof-of-concept data extraction).

* **Motivation:** Financial (blackmail).

* **MedDefense Relevance:** Medium-High; broken access control on the patient portal (web-srv-01) provides a direct vector for silent data extraction.

## Summary Table

| Report | Actor Type | Motivation | MedDefense Risk |
| --- | --- | --- | --- |
| A | Nation-state | Espionage | Low |
| B | RaaS | Financial | CRITICAL |
| C | Hacktivist | Political | Low |
| D | Malicious Insider | Revenge | HIGH |
| E | Opportunistic | Financial | HIGH |
| F | Shadow IT | Convenience | HIGH |
| G | Unclear | Data Fraud | HIGH |
| H | Extortionist | Blackmail | Medium-High |
