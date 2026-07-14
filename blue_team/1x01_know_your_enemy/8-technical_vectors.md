# 8. The Technical Vectors

## 1. Vulnerable Software

* **Vector Category:** Vulnerable Software
* **MedDefense Evidence:** Apache 2.4.29 on `billing-srv-01` and Ubuntu 18.04 LTS (End-of-Life).
* **Affected Asset(s):** `billing-srv-01`, legacy web application servers.
* **Actor Most Likely to Exploit:** Unskilled/Opportunistic Attacker.
* **Exploitation Scenario:** An attacker identifies the EOL version of Apache via automated scanning and exploits known CVEs to gain remote code execution (RCE). This establishes an initial foothold on the billing server.
* **Current Protection:** Perimeter firewall (partial filtering).
* **Gap Reference:** Web-01 (Unpatched CMS/Software).

## 2. Unsupported Systems

* **Vector Category:** Unsupported Systems
* **MedDefense Evidence:** Windows XP (MRI workstation) and Windows Server 2012 R2 (`print-srv-01`).
* **Affected Asset(s):** MRI imaging suite, Print Server.
* **Actor Most Likely to Exploit:** Nation-State APT.
* **Exploitation Scenario:** APT actors utilize publicly available exploits for these unsupported OS versions to bypass security controls. Once exploited, these systems act as stable platforms for long-term persistence within the clinical network.
* **Current Protection:** Limited network air-gapping.
* **Gap Reference:** Sys-01 (Unsupported/Legacy OS).

## 3. Open Service Ports

* **Vector Category:** Open Service Ports
* **MedDefense Evidence:** MySQL (3306) and PostgreSQL (5432) accessible network-wide; RDP (3389) on workstations.
* **Affected Asset(s):** `billing-srv-01`, `ehr-db-01`, managed workstations.
* **Actor Most Likely to Exploit:** Ransomware Groups.
* **Exploitation Scenario:** Ransomware affiliates scan for open database ports to perform unauthorized queries or brute-force logins. Open RDP ports are then leveraged to gain administrative access via compromised credentials.
* **Current Protection:** Basic host-based firewalls (intermittent).
* **Gap Reference:** Net-02 (Open service ports).

## 4. Default Credentials

* **Vector Category:** Default Credentials
* **MedDefense Evidence:** PACS shared account, BD Alaris pump interfaces.
* **Affected Asset(s):** Imaging storage, medical infusion devices.
* **Actor Most Likely to Exploit:** Ransomware Groups.
* **Exploitation Scenario:** Attackers use documented default passwords to authenticate into medical IoT devices. This access is then used to bridge into the clinical network or disrupt infusion therapy.
* **Current Protection:** None (Credentials remain factory default).
* **Gap Reference:** IAM-04 (Default/Weak Credentials).

## 5. Unsecure Networks

* **Vector Category:** Unsecure Networks
* **MedDefense Evidence:** Flat network topology; Westside consumer router usage; lack of WiFi isolation.
* **Affected Asset(s):** All clinical and administrative systems.
* **Actor Most Likely to Exploit:** Ransomware Groups.
* **Exploitation Scenario:** The absence of network segmentation allows an attacker to pivot from a guest WiFi compromise directly to the EHR server. The flat network ensures that internal traffic to databases is not inspected or restricted.
* **Current Protection:** None (Global network access).
* **Gap Reference:** Net-04 (Flat network architecture).

## 6. Removable Devices / Unmanaged Endpoints

* **Vector Category:** Removable Devices / Unmanaged Endpoints
* **MedDefense Evidence:** No USB restriction GPO; unmanaged iPads used for clinical entry; shadow IT devices.
* **Affected Asset(s):** All clinical workstations and EHR-connected mobile devices.
* **Actor Most Likely to Exploit:** Insider (Negligent).
* **Exploitation Scenario:** An employee connects a personal, infected USB drive to a workstation to transfer documents, bypassing perimeter defenses. Alternatively, an unmanaged iPad acts as an entry point for malware into the internal network.
* **Current Protection:** Basic endpoint AV.
* **Gap Reference:** End-01 (Endpoint/USB Policy).
