# 2: The Symptom Trap

## Diagnostic Analysis: billing-srv-01

### 1. Kworker Process Identification

**What It Is:** Monero cryptocurrency miner masquerading as a legitimate Linux kernel process. Legitimate `kworker` processes run as root in brackets `[kworker]`; this malware runs as `www-data` from `/var/www/html/.cache/kworker`.

**What It Does:**
- Mines Monero cryptocurrency using 4 CPU cores
- Consumes **94.2% CPU** (PID 8834), explaining performance degradation
- Connects to 3 mining pools (pool.monero.org:4443, 91.121.87.10:8080, 104.238.140.32:3333)
- Deployed 14 days ago; configured for persistence (`"background": true`)
- Mining time accumulated: 16,421 minutes (11+ days of continuous operation)

**Evidence:** Binary `/var/www/html/.cache/kworker` (2.1 MB), config.json with wallet address and pool URLs, netstat showing 3 established connections to mining pools from PID 8834.

### 2. Real Compromise: Two Primary CIA Violations

**Visible Symptom:** Availability impact (slow billing app)

**Actual Violations:**

**Integrity (PRIMARY & DIRECT):**
- Attacker wrote malware binary and configuration to `/var/www/html/.cache/` without authorization
- System integrity breached; unauthorized files persist across reboots
- **Keyword:** Unauthorized modification, system compromise, persistence

**Confidentiality (PRIMARY & CAPABILITY-BASED):**
- Malware runs as `www-data` with read access to MySQL database (patient billing data, payment cards, SSNs, PHI for 50,000+ patients)
- Attacker demonstrated code execution in privileged context; can access sensitive data at will
- Even if not actively exfiltrating now, capability exists to steal protected health information
- **Keywords:** Unauthorized access, code execution, patient data exposure, PHI compromise

**Availability (SECONDARY):**
- 94.2% CPU degradation is collateral damage from mining, not the root cause
- Performance would be threatened regardless of billing workload

### 3. Why Hardware Upgrade Fails

**Sysadmin's Diagnosis:** "Server undersized. Upgrade to 16GB RAM, 8 vCPUs."

**Why It Fails:**
-  Malware migrates to new hardware; attacker gains upgraded platform for mining
-  Unpatched Apache RCE vulnerability persists; re-infection occurs again
-  Root cause (Apache 2.4.29 exploitability) not addressed
-  Attacker retains control; can deploy additional payloads (ransomware, backdoor, data exfiltration)
-  Temporary performance improvement, then degradation returns

**Correct Response:** Isolate → Patch Apache to 2.4.54+ → Reset credentials → Forensically analyze → Clean rebuild

### 4. Connection to January Ransomware Incident

**Pattern:** Same server compromised twice (January ransomware, June crypto-miner) = unpatched vulnerability.
s
**Root Cause:** **Apache 2.4.29 RCE vulnerability**
- January: Attacker exploited Apache RCE → ransomware
- January rebuild: Server rebuilt but Apache NOT upgraded/patched
- June (14 days ago): Attacker re-exploited same Apache RCE → crypto-miner
- Cycle repeats: Sysadmin restarts server 3 times in 2 months; miner returns

**Critical Failures:**
- Post-incident rebuild did not include vulnerability patching
- Apache version unchanged (2.4.29 has known RCE CVEs)
- No EDR to detect malware deployment
- No automated vulnerability scanning

**Critical Questions:**
1. **How did attacker regain access?** → Unpatched Apache RCE (same entry point)
2. **Was forensic analysis conducted?** → Unknown; if yes, missed the vulnerability
3. **Were credentials reset?** → Unknown; if not, attacker may have stored credentials
4. **Was Apache patched during rebuild?** → No evidence; same vulnerable version
5. **What data was accessed/exfiltrated in Jan incident?** → Unknown; scope not documented
6. **Is data exfiltration occurring now?** → Unknown; attacker has read access to entire database (50K+ patient records)

## Summary Table

| Question | Finding | CIA Impact | Severity |
|----------|---------|-----------|----------|
| What is kworker? | Monero miner running as www-data | Integrity, Confidentiality | CRITICAL |
| Primary compromise? | Unauthorized code execution + write access to billing server | Integrity, Confidentiality | CRITICAL |
| Why hardware upgrade fails? | Root cause (Apache RCE) unaddressed; malware persists | Confidentiality, Integrity | CRITICAL |
| Connection to Jan incident? | Same unpatched vulnerability exploited twice; incomplete rebuild | Persistent Compromise | CRITICAL |
