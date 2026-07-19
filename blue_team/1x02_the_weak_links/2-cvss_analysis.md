# 2. The CVSS Deconstruction

## Exercise 1: Deconstruction (CVE-2021-44790)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Score: 9.8)

| Component | Abbreviation | Meaning | Why Selected |
| --- | --- | --- | --- |
| **Attack Vector** | AV:N | Network | Remotely exploitable over the internet. |
| **Attack Complexity** | AC:L | Low | No specialized conditions or defenses to bypass. |
| **Privileges Req.** | PR:N | None | Attacker does not require authenticated access. |
| **User Interaction** | UI:N | None | Successful without any victim action. |
| **Scope** | S:U | Unchanged | Vulnerability impact limited to the component. |
| **Confidentiality** | C:H | High | Total loss of data confidentiality. |
| **Integrity** | I:H | High | Total loss of data integrity. |
| **Availability** | A:H | High | Total loss of availability (DoS). |

* **Other Values:** Changing **AV:N (Network)** to **AV:L (Local)** or **AV:P (Physical)** drastically lowers the score by restricting accessibility.
* **Change to AV:L:** The new score is **8.4 (High)**.
* **Why the score is 8.4:** The score drops from 9.8 to 8.4 because the Attack Vector shifts from "Network" to "Local," meaning the attacker must now have physical or logical access to the specific machine. However, the score remains high (8.4) because all three impact metrics (Confidentiality, Integrity, and Availability) are still set to "High." The severity of the exploit itself—full system compromise—remains intact; the only change is the reduction in the number of potential attackers who can reach the vulnerability.

## Exercise 2: Construction

**Scenario:**

* Exploitable only from the local network (`AV:A`)
* Exploitation is complex (`AC:H`)
* Low-level privileges required (`PR:L`)
* No user interaction (`UI:N`)
* Scope unchanged (`S:U`)
* Confidentiality: High (`C:H`), Integrity/Availability: None (`I:N`, `A:N`)

**Vector String:** `CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Calculated Score:** **5.1 (Medium)**

## Exercise 3: Comparison

| Finding | Vector | Score | Severity |
| --- | --- | --- | --- |
| **Finding 001** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| **Finding 005** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` | **5.6** | Medium |

* **Analysis:** The primary difference is the impact on **Integrity (I)** and **Availability (A)**, combined with **Attack Complexity (AC)**.
* **Biggest Impact:** The biggest drivers of the score difference are the Impact metrics and the Complexity metric. Finding 001 is "Critical" (9.8) because it allows an attacker to bypass all controls (`AC:L`) and gain full read/write/delete access (`H/H/H`). Finding 005 is "Medium" (5.6) because the attacker faces higher complexity (`AC:H`) and, even if successful, can only achieve limited impact (`L/L/L`) on the Confidentiality, Integrity, and Availability of the system. This demonstrates how access to data (Confidentiality) does not inherently constitute a "Critical" vulnerability unless combined with the ability to alter or destroy that data (Integrity/Availability).
