# 14. The Network Posture

### Segmentation Impact Analysis

| Vulnerability | Host | CVSS Score | Flat Network (Current) Impact | Segmented Network (Hypothetical) Impact |
| --- | --- | --- | --- | --- |
| **CVE-2019-9193** (PostgreSQL RCE) | `billing-srv-01` | 7.2 | **High:** Any host on the 10.10.0.0/16 subnet can reach the database port and execute arbitrary code. | **Low:** Only authorized application servers can reach the DB; lateral movement is blocked at the VLAN gateway. |
| **CVE-2017-8563** (LDAP Relay) | `DC-01` | 8.1 | **Critical:** Every endpoint can reach the DC to initiate relay attacks, enabling domain-wide privilege escalation. | **Moderate:** Only authenticated server subnets can reach the DC; relay vectors are significantly reduced. |
| **CVE-2022-21663** (Object Injection) | `Grafana-srv` | 7.2 | **Moderate:** A compromised workstation can reach this service, allowing for authentication bypass and further internal access. | **Low:** Access restricted to management/admin VLANs; the breach remains localized to the administrative zone. |


### Risk Amplification Factor

The "Amplification Factor" is the ratio of potential impact in a flat vs. segmented network. For MedDefense, this factor is **high**.

* **CVE-2019-9193** risk is amplified by ~5x because the database is reachable by every device on the network rather than just the application tier.
* **CVE-2017-8563** risk is amplified by ~10x because the flat network allows "any-to-any" connectivity, which is the exact prerequisite for NTLM relay attacks to succeed against a Domain Controller.
* **CVE-2022-21663** risk is amplified by ~3x because the internal server is exposed to every infected workstation, turning a server-side exploit into an accessible lateral movement vector.

### What is the aggregate risk amplification effect of the flat network across the entire scan report ? Why is network segmentation arguably more impactful than patching any single CVE ?

The aggregate risk amplification effect of the flat network is that it renders individual vulnerability remediation nearly futile; as long as the network remains flat, an adversary only needs to be "right once" to gain broad access to the entire environment. Patching a single CVE fixes the hole, but it does not remove the adversary’s ability to move through the wall once they find a different gap, whereas segmentation effectively turns the entire building into a series of isolated vaults. Therefore, network segmentation is arguably more impactful than patching; while patching reduces the *number* of entry points, segmentation reduces the *utility* of every single one of them, preventing a minor compromise on a low-value asset from escalating into a full-scale clinical or financial data breach.
