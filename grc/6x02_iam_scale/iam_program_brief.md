# Brief the CISO on the Identity Program

**TO:** Board Risk Committee | **DATE:** Nov 14, 2026 | **RE:** Access Control Gaps Three Months After the Breach

## The Immediate Risk (Why This Matters)

Our post-breach audit identified **14 serious access control failures**—the majority **still in place today**. These gaps directly enabled the attack and create immediate re-occurrence risk:

**Five automated system accounts have administrative access and haven't been touched in years.** When attackers compromise an employee's computer, they steal these old credentials and gain full control. This is exactly how the breach spread. We can remediate this in 48 hours by removing these unnecessary privileges. *(Evidence: IAM Audit Report, Findings 001, 002, 003)*

**Two employees who left the company still have active network access.** Their login passwords work today on clinical and financial systems. This mirrors the off-boarding failure from the original breach. We can disable them immediately. *(Evidence: IAM Audit Report, Findings 004, 005, 008)*

**Patient backup data is publicly accessible on the internet.** Our AWS S3 bucket containing medical record backups (patient names, diagnoses, medications, test results) has no authentication. Any user on the internet can download it. This constitutes a HIPAA regulatory breach. We can block it in one hour. *(Evidence: Cloud Security Assessment, Finding 6)*

**Only 45% of system administrators use two-factor authentication.** One stolen password = one critical system under attacker control. *(Evidence: IAM Audit Report, MFA Coverage)*

## What We're Doing Now (By Nov 21)

| Action | Impact | Owner | Date |
|---|---|---|---|
| Disable 3 departed employees; remove automatic system privileges from 3 more accounts | Closes the exact breach attack path | IT Security | Nov 21 |
| Block internet access to patient backup data; audit for past unauthorized access | Stops immediate HIPAA breach exposure | Cloud Security | Nov 15 |
| Require two-factor authentication for all system administrators | Stops credential-only compromise | IT Operations | Nov 21 |

## What We Need Board Authorization For (Long-Term Fix)

**The Problem:** Our current approach is reactive—we find gaps, we patch them, but we have no system to prevent new gaps. Without permanent controls, this will happen again.

**The Solution ($225K, 18 months):**
1. **Automated credential management ($150K):** System automatically rotates administrative passwords every 30 days; staff no longer know the passwords (eliminates stolen credential risk)
2. **Account-level guardrails ($50K):** Prevent developers from giving themselves unnecessary permissions; flag policy drift automatically
3. **Two-factor authentication hardware ($25K):** Distribute FIDO2 security keys to 50+ administrators (passwords alone are no longer sufficient)
4. **Quarterly reviews (staff absorbed):** Force managers to re-certify that each employee still needs their access level

**If We Don't Do This:** Service account passwords remain unchanged; departed employees' accounts can be re-enabled; MFA stays at 45%. In 90 days, new gaps will appear and we'll be back here.

## Board Resolution

**RESOLVED, that the Board Risk Committee authorizes the Chief Information Security Officer to implement an 18-month Identity Security Program with $225K budget and Q3 2027 completion date; with immediate remediation of all 14 critical findings by November 21, 2026.**
