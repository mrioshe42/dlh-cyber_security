# 12. The Legacy Systems

An end-of-life (EOL) system is fundamentally different from a standard "unpatched" system because it exists in a state of **permanent vulnerability**. Unlike a supported system, where a vendor provides a path to remediation, an EOL system has no official security trajectory; any vulnerability discovered today or in the future will remain uncorrected by the vendor, meaning you are effectively running software that attackers can study, exploit, and weaponize with zero hope of a defensive patch.

### System 1: Windows XP SP3 (MRI Workstation)

* **EOL Research:** Microsoft ended support in 2014. While the NVD no longer tracks patches *for* XP, the OS shares the NT kernel architecture with later versions. Critical CVEs affecting legacy SMB/RDP (e.g., BlueKeep-style RCEs) remain permanently exploitable.
* **Permanent Exposure:** You cannot patch this risk because the vendor has ceased all security development; every new exploit discovered for the Windows NT architecture effectively becomes a "zero-day" for this system that will never be closed.
* **Scan Findings:** Likely to flag SMBv1 vulnerabilities (EternalBlue), lack of modern encryption (SSL/TLS v1.0/1.1), and weak password storage. These are directly exploitable because the OS lacks modern memory protections (ASLR/DEP) and kernel-level mitigations.
* **Compensating Controls:** The current controls (VLAN isolation, AppLocker, Gateway, Monitoring) are strong but rely on "perfect" implementation.
* *Adequacy:* They address network-level risk but do not stop local-access attacks (e.g., a technician plugging in an infected USB).
* *Recommended:* Add physical port locks and disable all non-essential USB mass storage via group policy or hardware blockers to prevent local vector exploitation.

### System 2: Windows Server 2012 R2 (Print Server)

* **EOL Research:** Support ended in Oct 2023. Recent criticals (e.g., **CVE-2025-59287**, a critical 9.8 RCE in WSUS, and **CVE-2025-27486**, a DoS flaw) affect this version, but without an active ESU (Extended Security Update) contract, these remain unpatched.
* **Permanent Exposure:** The risk is perpetual because the attack surface continues to grow with new research, while the defensive capability of the server remains frozen in 2023.
* **Scan Findings:** Likely to flag outdated TLS/cipher suites, potential RCEs in server services (like SMB or Print Spooler), and unpatched management agents. These are inherently exploitable due to the OS being incapable of receiving modern hotfixes.
* **Compensating Controls:** Proposed controls from the MRI (VLAN isolation/Gateway) would be effective here.
* *Recommended:* Since this is a print server, restrict its outbound traffic completely. It needs access to the print spooler and nothing else. Implementing a strictly hardened "Print Server Only" firewall profile would mitigate much of the RCE risk.

### System 3: Ubuntu 18.04 LTS (Billing Server)

* **EOL Research:** Standard support ended May 2023. Numerous high-priority kernel CVEs (e.g., **CVE-2026-53359**, a use-after-free RCE) are documented for newer kernels but apply to the underlying architectures that 18.04 relies on, leaving this server exposed.
* **Permanent Exposure:** The OS has outlived its security lifecycle; it is effectively "rotting" code that cannot defend itself against current exploit techniques used by ransomware affiliates.
* **Scan Findings:** Likely to flag outdated libraries (OpenSSL, glibc), known crypto-miner persistence (from previous breach history), and weak shell hardening. It is exploitable because the kernel and user-space binaries lack the security mitigations (like newer stack canaries or control-flow integrity) present in current LTS releases.
* **Compensating Controls:** Current controls (like standard firewalls) are inadequate for a system already known to be compromised.
* *Recommended:* This system requires immediate EDR (Endpoint Detection and Response) deployment to monitor for the specific behavior of the previous crypto-miner. Given the billing sensitivity, it also requires strict egress filtering to prevent data exfiltration.

### Business Decision: Migration Priority

**Decision:** Migrate the **Ubuntu 18.04 Billing Server (10.10.2.15)** first.

**Justification:**

1. **Asset Criticality:** The billing server handles sensitive patient financial data and PHI (Protected Health Information). According to the Threat Exposure report (1x01), attackers target healthcare for data exfiltration; this system is the highest-value target for "Double Extortion" ransomware.
2. **Threat Exposure:** Unlike the MRI (which is physically segmented) or the Print Server (which has limited utility), this server is **already compromised** (the crypto-miner history). It serves as an active beachhead for threat actors.
3. **Risk Reduction:** Moving this server to a modern, supported OS (e.g., Ubuntu 24.04) with active patch management is the only way to break the current cycle of infection, providing the most immediate and substantial reduction in organizational risk.
