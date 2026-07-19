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

**Scenario Analysis and Mapping:**

* **Attack Vector (`AV:A`):** The scenario is "Exploitable only from the local network." This is strictly mapped to **Adjacent (AV:A)**, as it requires access to the shared local network segment (e.g., LAN/VLAN) and cannot be exploited via the broader internet (Network) or from the local machine (Local).
* **Attack Complexity (`AC:H`):** Exploitation is complex.
* **Privileges Required (`PR:L`):** Low-level privileges required.
* **User Interaction (`UI:N`):** No user interaction.
* **Scope (`S:U`):** Scope unchanged.
* **Confidentiality Impact (`C:H`):** Confidentiality is impacted highly.
* **Integrity Impact (`I:N`):** No integrity impact.
* **Availability Impact (`A:N`):** No availability impact.

**Vector String:** `CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Calculated Score:** **5.1 (Medium)**

## Exercise 3: Comparison

| Finding | Vector | Score | Severity |
| --- | --- | --- | --- |
| **Finding 001** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| **Finding 005** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` | **5.6** | Medium |

* **Analysis:** The primary differences between these findings are the **Attack Complexity (AC)** and the **Impact Metrics (Confidentiality, Integrity, and Availability)**.
* **Biggest Impact on Score:**
    1. **Impact Metrics (C, I, A):** These have the largest weight. Finding 001 provides total compromise (`H/H/H`), driving the score to Critical. Finding 005 only impacts the system to a limited degree (`L/L/L`), which drastically reduces the base score.
    2. **Attack Complexity (AC):** Finding 005 uses `AC:H`, which adds a barrier to entry, lowering the score compared to Finding 001 (`AC:L`), which allows for easier, reliable exploitation. 
* **Conclusion:** While both findings have similar network-based attack vectors, the severity difference is driven by the potential for full system compromise (Finding 001) versus limited impact (Finding 005).
