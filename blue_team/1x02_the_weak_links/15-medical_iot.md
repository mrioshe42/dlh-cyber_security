# 15. The Medical IoT

### BD Alaris Assessment

The BD Alaris infusion system vulnerability—specifically impacting older firmware versions—often relates to session authentication failures.

* **Vulnerability:** A network session authentication vulnerability exists within the process between the Alaris PC Unit and the Systems Manager, which can be exploited to cause a Denial-of-Service (DoS) condition on the PC Unit.
* **Vendor Recommendation:** BD recommends implementing network perimeter security, such as firewalls or Access Control Lists (ACLs), to limit traffic to required ports (e.g., port 3613 for Systems Manager) and segmenting Alaris PCUs onto a dedicated VLAN.
* **MedDefense Status:** Our team must verify if MedDefense has implemented these network segmentation and ACL restrictions. Given the flat network findings from previous tasks, it is highly likely these devices are currently reachable across the 10.10.0.0/16 subnet, leaving them exposed to any compromised workstation.

### Philips IntelliVue Assessment

Philips IntelliVue patient monitors serve as critical hubs for real-time physiological data, often including integrated HL7 ports for communication with clinical systems like the Patient Information Center iX (PIC iX).

* **Data Flows:** These monitors transmit vital sign data, alarms, and patient monitoring streams across the network to the PIC iX.
* **Attacker Capabilities:** An attacker with network access to these unauthenticated interfaces could potentially:
* Inject arbitrary observation results into HL7 v2.x messages, which could lead to misdiagnosis or incorrect treatment protocols.
* Cause DoS conditions by sending malformed input to the device, forcing a system restart and a loss of patient monitoring visibility.
* Monitor sensitive physiological data if the communication channel is intercepted or exposed.

### Patient Safety Dimension

Medical device vulnerabilities represent a "physical harm" risk category, distinct from the "data loss" risk of IT systems. While a compromised workstation leads to data exfiltration or credential theft, a compromised infusion pump or patient monitor directly threatens the delivery of care.

* **Worst-Case Scenario (Workstation):** Unauthorized access to sensitive PHI, resulting in a HIPAA breach and regulatory fines.
* **Worst-Case Scenario (Infusion Pump):** Manipulation of dosage delivery, which could result in direct patient harm, injury, or death.

### Remediation Challenge

Patching medical devices is significantly more complex than standard IT patching due to the following factors:

* **Regulatory Hurdles:** Medical device patches are often legally classified as design changes by regulatory bodies like the FDA, requiring the device to undergo the same rigorous validation and documentation processes as a new product.
* **Operational Disruptions:** Clinical environments require 24/7 availability. Patching requires downtime that can disrupt life-saving workflows, leading to clinical errors or the need for manual workarounds.
* **Vendor Dependency:** Unlike general-purpose OS patching, we are entirely dependent on the manufacturer for updates. Many legacy medical devices have hardcoded architectures or "locked" configurations that do not support modern security updates, forcing us to rely on compensating controls (like segmentation) rather than direct patching.
