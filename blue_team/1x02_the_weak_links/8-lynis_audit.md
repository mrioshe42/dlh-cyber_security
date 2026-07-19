# 8. The Self-Audit

### Part 2: Analysis Results

**Hardening Index:** 66

**Top 5 Critical Findings (Warnings & High-Impact Suggestions)**

| Finding | Impact | Remediation |
| --- | --- | --- |
| **Accounts without password** [AUTH-9283] | Unauthorized local access. | Run `passwd -l` to lock or set complex passwords. |
| **Time sync failure** [TIME-3185] | Breaks log correlation/SSL validation. | Enable/start `systemd-timesyncd`. |
| **GRUB protection** [BOOT-5122] | Allows unauthorized boot-time access. | Set password on GRUB boot loader. |
| **Missing Malware Scanner** [HRDN-7230] | Undetected persistence/rootkits. | Install `rkhunter` or `chkrootkit`. |
| **Service Hardening** [BOOT-5264] | Over-privileged system services. | Apply `systemd` security profiles. |

**Top 5 Relevant Suggestions**

1. **`fail2ban` [DEB-0880]:** Automated defense against SSH brute-force attacks.
2. **`auditd` [ACCT-9628]:** Essential for forensic file-access logging.
3. **File Integrity Monitoring [FINT-4350]:** Alerts on unauthorized changes to sensitive binaries.
4. **Password Aging [AUTH-9286]:** Enforces credential rotation in `/etc/login.defs`.
5. **WAF Modules [HTTP-6643]:** Protects Apache against web application exploits.

**Category Breakdown**

* **Highest Score:** File System (permissions generally compliant).
* **Lowest Score:** Kernel/Services. The system lacks automated intrusion prevention and relies on default kernel parameters that require tightening.


### Part 3: MedDefense Projection (`billing-srv-01`)

If applied to `billing-srv-01`, Lynis would likely generate a "Critical" warning state based on the following:

1. **OS End-of-Life:** Ubuntu 18.04 is unsupported; Lynis will flag this as a critical failure due to lack of security patches.
2. **Weak SSH Config:** Password authentication enabled, likely missing key-based restriction hardening.
3. **Crypto-Miner Persistence:** Scans of `crontab` files will likely identify unauthorized scripts or malicious cron jobs left by previous compromise.
4. **MySQL Exposure:** High probability of `bind-address` set to `0.0.0.0` (all interfaces), exposing the database to the network.
5. **Information Disclosure:** Apache 2.4.29 likely defaults to showing server tokens (OS/version), providing attackers with a roadmap for exploit selection.
