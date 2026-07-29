# 0. The Advisory Analysis

## Phase 1: Initial Access

**Advisory Description:**  
Attackers gain initial network entry through perimeter or remote asset exploitation.

**MedDefense Mapping**

- **Target System:** `web-srv-01` (Patient Portal)
- **Vulnerability Reference:** Finding 031 (Ghostcat RCE)
- **Gap Reference:** GAP-004 (Net-01)
- **Crypto Weakness:** Weak TLS 1.0/1.2, expired certificate
- **Current Protection:** Perimeter firewall (C-001)
- **Verdict:** **EXPOSED**

## Phase 2: Execution & Persistence

**Advisory Description:**  
Attackers establish persistence using scheduled tasks or compromised credentials.

**MedDefense Mapping**

- **Target System:** `billing-srv-01`
- **Vulnerability Reference:** Finding 003 (SQL Injection) / Crypto-miner incident
- **Gap Reference:** GAP-002, GAP-008
- **Crypto Weakness:** Unencrypted filesystems, plaintext credentials
- **Current Protection:** Sophos Endpoint Protection (C-003, limited)
- **Verdict:** **EXPOSED**

## Phase 3: Privilege Escalation

**Advisory Description:**  
Attackers escalate privileges to domain administrator access.

**MedDefense Mapping**

- **Target System:** `ad-dc-01`, `ad-dc-02`
- **Vulnerability Reference:** Finding 007 (LDAP Relay)
- **Gap Reference:** GAP-008 (IAM-05)
- **Crypto Weakness:** NTLM (NT Hash/MD4), Kerberos RC4/DES
- **Current Protection:** Active Directory access controls
- **Verdict:** **EXPOSED**

## Phase 4: Defense Evasion

**Advisory Description:**  
Attackers disable or evade security monitoring to remain undetected.

**MedDefense Mapping**

- **Target System:** Organisation-wide infrastructure
- **Vulnerability Reference:** Unmonitored internal network
- **Gap Reference:** GAP-002 (No SIEM/IDS)
- **Crypto Weakness:** None
- **Current Protection:** Perimeter firewall only
- **Verdict:** **EXPOSED**

## Phase 5: Lateral Movement

**Advisory Description:**  
Attackers pivot across the internal network to reach high-value systems.

**MedDefense Mapping**

- **Target System:** Medical IoT and `ehr-db-01`
- **Vulnerability Reference:** Finding 010 (Alaris Pump Unauthenticated Access)
- **Gap Reference:** GAP-001 (Net-04)
- **Crypto Weakness:** Unencrypted internal network traffic
- **Current Protection:** Flat internal network protected only by perimeter firewall
- **Verdict:** **EXPOSED**

## Phase 6: Data Exfiltration

**Advisory Description:**  
Attackers steal sensitive patient records and organisational data.

**MedDefense Mapping**

- **Target System:** `ehr-db-01`, `pacs-srv-01`
- **Vulnerability Reference:** Finding 003 / Unencrypted storage
- **Gap Reference:** GAP-003
- **Crypto Weakness:** Unencrypted ext4 database volumes
- **Current Protection:** Active Directory access controls (C-005)
- **Verdict:** **EXPOSED**

## Phase 7: Impact / Ransomware Deployment

**Advisory Description:**  
Attackers encrypt production systems and backups to demand payment.

**MedDefense Mapping**

- **Target System:** `backup-srv-01` (NAS-01)
- **Vulnerability Reference:** Co-located backup NAS
- **Gap Reference:** GAP-007
- **Crypto Weakness:** Plaintext NAS storage
- **Current Protection:** UPS (20-minute runtime)
- **Verdict:** **EXPOSED**

## Overall Assessment

- **Exposure Score:** **7/7 phases exposed**
- **Critical Finding:** Internet-facing web assets should be patched immediately and internal microsegmentation deployed to prevent lateral movement by the Crimson Tide threat actor.
