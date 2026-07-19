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
* **Change to AV:L:** The new score is **7.8 (High)**. The score drops because the attack vector is no longer reachable via the internet, limiting the potential attacker pool to someone already on the local system.

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
| **Finding 005** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |

* **Analysis:** The primary difference is the impact on **Integrity (I)** and **Availability (A)**.
* **Biggest Impact:** In this case, the `I` and `A` metrics are the primary drivers of the score difference. Because Finding 001 provides the attacker with full control (H/H/H) across all impact vectors, it reaches "Critical" status, whereas Finding 005, which only allows confidentiality loss (H/N/N), is capped at "High."
