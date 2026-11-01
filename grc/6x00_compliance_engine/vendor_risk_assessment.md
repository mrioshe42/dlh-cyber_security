Vendor: CloudVault Medical | Service: Clinical backup + DR archive | Tier: A (ePHI)
Assessed: 2026-11-1 | ePHI exposure: Yes


## Findings

| # | Item | Response | Rating | Action Required |
|---|---|---|---|---|
| 1 | SOC 2 II | Yes; 11 mo | **Pass** | Accept |
| 2 | HITRUST | No | OK | SOC 2 sufficient |
| 3 | Encryption (rest) | AES-256 | **Pass** | Accept |
| 4 | Encryption (transit) | TLS 1.2 | **Pass** | Accept |
| 5 | Pentest | 22 mo old; no findings | **CRITICAL** | Provide ≤12mo pentest + remediation |
| 6 | Sub-processors | US CDN + EU analytics | **Concern** | Disclose MetricLake data scope + HIPAA binding |
| 7 | DR site location | Not disclosed | **Concern** | Disclose jurisdiction; confirm US-only |
| 8 | Incident notification | 72 hours | **CRITICAL** | BAA must specify 24 hours |
| 9 | Data deletion | 90 days | **Concern** | BAA must specify 30 days max |
| 10 | Background checks | At hire only | **Concern** | Annual checks for ePHI staff |
| 11 | MFA | Yes; TOTP | **Pass** | Accept |
| 12 | Vuln management | Monthly scan; Q remediation | **Pass** | Accept |
| 13 | Right-to-audit | 60-day notice | **Concern** | Reduce to 30 days; immediate for incidents |
| 14 | BAA | Willing (unsigned) | **CRITICAL** | Execute before any ePHI transfer |
| 15 | PHI training | Annual online | OK | Require completion records |

## Critical Issues (3)

**#5 Pentest (22 months old):** Policy requires ≤12 months. Outdated evidence = insufficient vendor vetting per OCR standards. **Blocker:** Independent pentest ≤12 months with findings summary + remediation status required before ePHI access.

**#8 Incident notification (72 hours):** Policy requires 24 hours. 72-hour delay = MedDefense cannot meet HIPAA Breach Notification timelines; patient safety and regulatory risk. **Blocker:** BAA must mandate 24-hour notification (non-negotiable).

**#14 BAA (unsigned):** Policy unconditional: no ePHI without executed BAA. Intent ≠ agreement. **Blocker:** BAA must be fully signed by both parties before contract execution; no data transfer under unsigned BAA.

## Recommendation: APPROVE WITH CONDITIONS

**Pre-execution blockers (must complete before contract signature):**
1. Executed BAA with: 24h incident notification, 30-day data deletion, audit rights, subprocessor flow-down, indemnification
2. Pentest ≤12 months + findings summary + remediation proof
3. MetricLake disclosure: data exposure scope + HIPAA-binding contract terms
4. DR location + jurisdiction disclosure (US-only or document cross-border implications)

**Post-execution (30 days after signature):**
5. Annual background re-checks for ePHI staff (recommended)
6. Right-to-audit: reduce 60-day notice to 30 for routine; immediate for incidents

**Approval:** IT Security + Procurement (pending CISO)  
**Conditions due:** 2026-11-15  
**Contract blocked until:** All 4 pre-execution blockers satisfied + signed by Legal


**Assessed by:** _________________ | Date: _______ | CISO: _______
