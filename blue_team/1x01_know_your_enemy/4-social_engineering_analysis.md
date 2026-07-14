# 4. The Human Vector

## Scenarios

1. **Fake Firmware Update:** Phishing impersonating Fortinet targeting the IT Director via a typosquatted domain. Leverages Authority and Urgency to force malware download instead of a patch.

2. **Fake CEO Wire Transfer:** BEC targeting the CFO. Uses Authority (CEO) and Exclusivity to bypass financial controls for an $85,000 fraudulent transfer.

3. **Vishing Attack:** Pretexting a nurse to steal EHR credentials under the guise of an "emergency security audit." Exploits clinical helpfulness and stress.

4. **Parking SMS (Smishing):** Mass phishing via SMS targeting employees with fake permit renewals. Harvests Active Directory credentials via typosquatted portals.

5. **Watering Hole:** Compromised Healthcare Association CME website. Silently exploits physician workstations via browser vulnerabilities to gain persistent access.

6. **Typosquatted Portal:** Paid Google Ads leading to a pixel-perfect fake patient portal. Harvests patient credentials and identity data.

7. **Physical Tailgating:** Impersonating staff to infiltrate the IT corridor. Uses props (scrubs, stethoscopes) to exploit staff reluctance to challenge unauthorized entries.


## Vector Classification

| Scenario | Vector | Target | Lever |
| --- | --- | --- | --- |
| 1 | Phishing/Impersonation | IT Director | Authority/Fear |
| 2 | BEC | CFO | Authority/Urgency |
| 3 | Vishing | Nurse | Helpfulness/Authority |
| 4 | Smishing | Employees | Complacency/Urgency |
| 5 | Watering Hole | Physicians | Trust/Silent |
| 6 | Typosquatting | Patients | Authority/Trust |
| 7 | Tailgating | IT Staff | Social Discomfort |

## Pattern Analysis

MedDefense is systemically vulnerable due to three factors:

* **Healthcare Culture:** Prioritizes responsiveness and helpfulness, creating a social engineering paradise where staff assist attackers instead of verifying them.

* **Inconsistent Controls:** MFA and technical safeguards (EDR/DLP) are patchily deployed, leaving vast areas of the network exposed.

* **Training Gaps:** Awareness is generic and lacks scenario-based training. Employees know "don't share passwords" but cannot detect sophisticated pretexting or vishing.

## Key Controls

* **Technical:** Mandatory MFA on all systems, DMARC/SPF/DKIM enforcement, EDR deployment, URL reputation filtering, and badge systems with photo verification.

* **Administrative:** Scenario-based security training, strict vendor/wire-transfer verification policies, and "no door-holding" physical security enforcement.
