# 16. The Noise Filter

### Finding Triage List

| Finding [ID] | [CVSS or Severity] | [Host] | Category: [AC/AS/I/FP] | Reason |
| --- | --- | --- | --- | --- |
| **001** | Med | Web-srv-01 | **AS** | SSL/TLS Cipher suite configuration requires hardening. |
| **002** | Med | Web-srv-01 | **AS** | Outdated TLS version enabled on web interface. |
| **003** | Crit | Billing-srv | **AC** | Database vulnerability on high-value billing asset. |
| **004** | Crit | MRI-Workstn | **AC** | End-of-Life OS (XP) with permanent critical vulnerabilities. |
| **005** | Med | Internal-srv | **AS** | SSH configuration allows weak cipher negotiation. |
| **006** | Crit | Billing-srv | **AC** | Critical application flaw exposes patient data. |
| **007** | Crit | DC-01 | **AC** | LDAP Relay vulnerability allows domain-wide compromise. |
| **008** | Med | All Hosts | **AS** | SMB signing not required; susceptible to MiTM. |
| **009** | Med | All Hosts | **AS** | Local Guest account is enabled by default. |
| **010** | Crit | Alaris-Pump | **AC** | Medical device vulnerability affects patient dosing control. |
| **011** | Med | Billing-srv | **AS** | Unpatched library vulnerability in billing backend. |
| **012** | Low | Web-srv-01 | **I** | Missing security headers (Content-Security-Policy). |
| **013** | Med | Network-dev | **AS** | SNMP community string set to default "public". |
| **014** | Info | All Hosts | **FP** | NTP configuration is correct; misidentified by scanner. |
| **015** | Med | NAS-01 | **AS** | NAS web management interface exposed to internal network. |
| **016** | Crit | Philips-Mon | **AC** | Medical device exposes unauthenticated clinical data port. |
| **017** | Med | Web-srv-01 | **AS** | Tomcat version disclosure provides intelligence for exploitation. |
| **018** | Med | All Hosts | **AS** | Password policy does not enforce complexity requirements. |
| **019** | Med | All Hosts | **AS** | Stale user accounts remain active on the domain. |
| **020** | Info | DC-01 | **FP** | Kerberos settings verified; correctly configured for legacy. |
| **021** | Low | Web-srv-01 | **I** | HTTP TRACE method enabled, low impact in this context. |
| **022** | Med | Billing-srv | **AS** | Java runtime environment requires critical security update. |
| **023** | Med | Billing-srv | **AS** | .NET framework version is deprecated. |
| **024** | Crit | IoT-Gateway | **AC** | Unauthorized access to medical IoT management portal. |
| **025** | Med | Print-srv | **AS** | DNS misconfiguration allows zone transfer information leak. |
| **026** | Med | Print-srv | **AS** | Print spooler service vulnerability. |
| **027** | Crit | Billing-srv | **AC** | EDR/Security agent is inactive, leaving host undefended. |
| **028** | Low | All Hosts | **I** | ICMP Timestamp response enabled. |
| **029** | Crit | Grafana-srv | **AC** | Critical vulnerability in Grafana version. |
| **030** | Crit | Legacy-srv | **AC** | Telnet enabled; cleartext credentials in transmission. |
| **031** | Crit | Web-srv-01 | **AC** | Ghostcat vulnerability allows RCE via AJP connector. |

### Triage Summary

| Category | Count | Definition |
| --- | --- | --- |
| **Actionable Critical (AC)** | 11 | High risk, immediate remediation required. |
| **Actionable Standard (AS)** | 16 | Real vulnerability, planned remediation required. |
| **Informational (I)** | 3 | Low risk or observational. |
| **False Positive (FP)** | 2 | Not a vulnerability. |

### Actionable Findings List

This list ranks findings by priority, focusing on internet-facing RCEs and critical assets first.

**Priority 1: Actionable Critical (Immediate Remediation - 24/48h)**

1. **Finding 031 (Ghostcat)**: Internet-facing RCE.
2. **Finding 003 (Billing Database)**: Critical exposure of high-value PHI.
3. **Finding 007 (LDAP Relay)**: Direct path to domain-wide compromise.
4. **Finding 010 (Alaris Pump)**: Direct patient safety risk.
5. **Finding 016 (Philips Monitor)**: Direct patient safety risk.
6. **Finding 024 (IoT Gateway)**: Critical infrastructure access.
7. **Finding 027 (Billing Agent)**: Lack of defense on primary target.
8. **Finding 004 (MRI XP)**: Permanent vulnerability on critical asset.
9. **Finding 029 (Grafana)**: High-risk internal pivoting point.
10. **Finding 006 (Billing App)**: Secondary application risk on billing host.
11. **Finding 030 (Telnet)**: Cleartext credential exposure.

**Priority 2: Actionable Standard (Scheduled Remediation - 7-30 days)**

1. **Finding 013 (SNMP)**: Easy reconnaissance vector.
2. **Finding 017 (Tomcat Info)**: Intelligence gathering for exploit chains.
3. **Finding 015 (NAS Interface)**: Lateral movement risk.
4. **Finding 022/023 (Java/.NET)**: OS-level hardening.
5. **Finding 001/002 (SSL/TLS)**: Encryption hygiene.
6. **Finding 008/009/018/019 (Admin/Auth)**: Hardening user/network access.
7. **Finding 005 (SSH)**: Configuration hygiene.
8. **Finding 011 (Lib Vuln)**: Backend patching.
9. **Finding 025/026 (Print Server)**: Reducing service attack surface.
