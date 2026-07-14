# 6. The MedDefense Threat Actor Matrix

This matrix consolidates the identified threats to MedDefense, providing a strategic overview for Board-level risk oversight.

| Actor Type | Likelihood | Capability | Primary Motivation | Preferred Vector | Primary Target | MedDefense Exposure (Gaps) |
| --- | --- | --- | --- | --- | --- | --- |
| **Ransomware Groups** | Critical | High | Financial | Phishing/VPN Exploits | EHR & Backup Systems | Net-01, Net-04, BKP-02 |
| **Nation-State APT** | Medium | Very High | Espionage/Disruption | Supply Chain/Zero-Day | Medical Research Data | Sys-03, Net-05 |
| **Insider (Malicious)** | Low | Low-Med | Revenge/Financial | Privilege Abuse | Patient Records (PHI) | IAM-05, SEC-02 |
| **Insider (Negligent)** | Critical | N/A | Accidental | Social Engineering | Credentials/Endpoints | IAM-02, TRN-01 |
| **Hacktivist** | Medium | Medium | Ideological | DDoS/Defacement | Public-Facing Portals | Net-01, Web-01 |
| **Unskilled/Opportunist** | High | Low | Opportunistic | Scanning/Exploits | Exposed Services | Net-01, Net-03 |


## Top 3 Priority Ranking

### 1. Ransomware Groups (Organized Crime)

* **Justification:** This group represents the highest threat due to the convergence of extreme impact and high likelihood. As a healthcare provider, MedDefense faces an industry-wide "Tier 1" targeting status from groups that view patient care urgency as a force multiplier for extortion. With a documented 300% surge in healthcare ransomware and the use of double-extortion tactics to leak sensitive patient data, the operational and financial fallout (averaging millions in remediation) makes this the primary existential risk.

### 2. Negligent Insider

* **Justification:** While less "adversarial" in intent, the negligent insider represents a critical vulnerability because they are the weakest link in the security chain. Statistics show that 90% of breaches originate from human error, such as clicking on phishing simulations or mishandling credentials. Because MedDefense staff are highly targeted by insurers, partners, and vendors via email, a single lapse in judgement provides the initial access point that more sophisticated actors (like Ransomware groups) require to enter the network.

### 3. Nation-State APT

* **Justification:** Although the probability of a targeted attack is lower than that of commodity cybercrime, the potential impact is catastrophic. Nation-states have increasingly focused on healthcare to gather intelligence, undermine public confidence, or disrupt critical infrastructure. Their ability to deploy custom malware and exploit supply chain dependencies (e.g., medical device firmware or third-party maintenance software) allows them to bypass standard perimeter defenses that would stop less sophisticated attackers, potentially leading to long-term, stealthy data exfiltration of high-value research and patient PII.
