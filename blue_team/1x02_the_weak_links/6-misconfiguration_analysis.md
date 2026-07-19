# 6. The Misconfiguration Findings

### Misconfiguration Analysis

The following table details six critical misconfigurations identified in the scan. Unlike CVEs, which represent specific software flaws, these findings are architectural, operational, or policy-based failures.

| Finding ID | Host | Misconfiguration | Why No CVE? | Severity | Cross-Reference (1x00) | Comparable CVE Risk |
| --- | --- | --- | --- | --- | --- | --- |
| **003** | `ehr-db-01` | Unrestricted PostgreSQL Access | Config/Policy | **Critical** | T7 (Discrepancy Table) | CVE-2021-44790 |
| **006** | `billing-srv-01` | MySQL Bound to 0.0.0.0 | Configuration | **High** | T7 (Discrepancy Table) | CVE-2020-1938 |
| **007** | `ad-dc-01` | LDAP Signing Not Required | Config/Policy | **High** | T5 (Gap G-009) | CVE-2021-34527 |
| **014** | `Netgear-01` | Inadequate Consumer HW | Architectural | **Medium** | T7 (Asset A-017) | CVE-2021-43798 |
| **015** | `NAS-01` | Mgmt Interface Public | Deployment Error | **Medium** | T7 (Asset A-030) | CVE-2021-43798 |
| **019** | Workstations | RDP Unrestricted | System Policy | **Medium** | T7 (Discrepancy Table) | CVE-2019-0708 |

---

### Analysis of Misconfigurations

#### Finding 003: PostgreSQL Unrestricted Access

* **Why No CVE:** This is a feature of the database management system. The software is functioning as designed; the security failure lies in the implementation of the `pg_hba.conf` policy.
* **Severity Assessment:** **Critical.** The database holds ~50,000 patient records (1x00 T7). Without network restrictions, any compromised internal host has direct access to the database.
* **Cross-Reference:** 1x00 T7 (Discrepancy: Database accessibility for PostgreSQL).
* **Comparable CVE Risk:** CVE-2021-44790. Like the Apache buffer overflow, this misconfiguration allows an attacker to bypass intended authentication boundaries to reach sensitive data.

#### Finding 006: MySQL Unrestricted Network Binding

* **Why No CVE:** Binding a service to an interface is an administrative configuration task, not an inherent flaw in the MySQL binary.
* **Severity Assessment:** **High.** It allows lateral movement across the billing network and payment systems.
* **Cross-Reference:** 1x00 T7 (Discrepancy: MySQL port 3306 accessible from entire network).
* **Comparable CVE Risk:** CVE-2020-1938 (Ghostcat). Both allow unauthorized access to backend services that should only be accessible via specific internal application paths.

#### Finding 007: LDAP Signing Not Required

* **Why No CVE:** LDAP signing is an optional configuration requirement in Active Directory. Its absence is a policy decision or oversight, not a code defect.
* **Severity Assessment:** **High.** It permits relay attacks, which are common precursors to full domain compromise.
* **Cross-Reference:** 1x00 T5 (Gap G-009: No encryption for data in transit).
* **Comparable CVE Risk:** CVE-2021-34527 (PrintNightmare). Both represent architectural weaknesses that adversaries leverage to escalate privileges and move laterally within the domain.

#### Finding 014: Netgear Router

* **Why No CVE:** Using consumer-grade hardware (`A-017`) in an enterprise environment is an architectural choice, not a vulnerability in the firmware itself.
* **Severity Assessment:** **Medium (High Context).** It provides the pivot point for all Westside Clinic traffic and has no firewall.
* **Cross-Reference:** 1x00 T7 (Asset A-017 marked as "INADEQUATE").
* **Comparable CVE Risk:** CVE-2021-43798. Both facilitate path traversal/unauthorized access to network infrastructure.

#### Finding 015: NAS-01 Synology DSM

* **Why No CVE:** Exposing an admin interface is a deployment error; the interface exists to be used by admins, but shouldn't be reachable by everyone.
* **Severity Assessment:** **Medium.** It protects the primary backup repository.
* **Cross-Reference:** 1x00 T7 (Asset A-030: Management interface 5000/5001 accessible from entire network).
* **Comparable CVE Risk:** CVE-2021-43798. Like the path traversal vulnerability, this allows an attacker to interact with a system interface that should be restricted.

#### Finding 019: RDP Enabled

* **Why No CVE:** RDP is a legitimate remote management feature of Windows.
* **Severity Assessment:** **Medium.** Enabled RDP on ~320 workstations without restriction is a massive target for brute-force attacks.
* **Cross-Reference:** 1x00 T7 (Discrepancy: RDP enabled without network restriction).
* **Comparable CVE Risk:** CVE-2019-0708 (BlueKeep). While BlueKeep is a software bug, the *result* is the same: an exposed RDP port that allows an attacker to interact with the system.

---

### False Assurance Statement

The statement "Our CVE scan shows nothing critical, we are secure" provides dangerous false assurance because CVEs track *known code defects*, not *logical security failures*. Attackers often "live off the land" by abusing legitimate features, such as misconfigured database bindings, weak encryption policies, or exposed management interfaces, which appear as "authorized" traffic to security tools. A system can be perfectly patched against every known CVE and still be trivially compromised through misconfiguration. By focusing solely on CVEs, an organization ignores the operational reality that the majority of modern breaches—such as those involving databases or cloud infrastructure—stem from human error and architectural oversights rather than exploitable software bugs.
