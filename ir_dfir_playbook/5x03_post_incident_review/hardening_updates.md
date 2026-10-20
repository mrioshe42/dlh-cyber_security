# Hardening Updates: IR-2026-0414-01

Each change closes one or more gaps from gap_analysis.md. Gap IDs refer to that register.

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-006 (encoded hidden PowerShell and unsigned update.exe ran unblocked on WST-WS-031 and WST-WS-017)

**Configuration:**
- GPO: Computer Configuration > Preferences > Windows Settings > Registry (Action: Update)
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
- Value name: `__PSLockdownPolicy`
- Value type: REG_SZ
- Value data: `4`
- Apply to: the workstation OU for WST-WS-031, WST-WS-017 and LIS-WSIDE-01, then the wider clinical workstation class

**Effect:** Forces PowerShell into Constrained Language Mode, which blocks `Add-Type`, arbitrary .NET type loading, and COM object creation that encoded-command loaders depend on.

**Scope limit:** This value is machine-wide, not per-user. It also constrains administrators on the same machine. Applying it only to non-administrative accounts needs a WDAC or AppLocker script policy instead. Pilot that before rollout.

**Developer impact:** WST-WS-042 runs `build.ps1` through PowerShell (clean baseline, 2026-03-18). Test that script under the setting before the OU is enforced.

**Validation:** Sign in as a standard user and run `$ExecutionContext.SessionState.LanguageMode`. Expected output: `ConstrainedLanguage`.

## HRD-002: AppLocker Rule Restricting MSBuild.exe

**Closes:** GAP-008 (MSBuild loaded update.xml from `C:\Users\dmarsh\AppData\Local\Temp` on both hosts)

**Configuration:** AppLocker Executable rule collection, enforced, with two Deny rules for MSBuild.exe. The Deny targets a group of standard users, not Everyone. BUILTIN\Administrators and the named CI/CD service accounts are outside that group, so they keep execution. The rules cover the 64-bit .NET Framework path and the Visual Studio install path.

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="7c1e2a40-0d3b-4f6a-9b8e-1a2c3d4e5f60"
                  Name="Deny MSBuild.exe (.NET Framework 64-bit) for standard users"
                  Description="Blocks MSBuild inline-task execution (GAP-008)"
                  UserOrGroupSid="S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\*\MSBuild.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="8d2f3b51-1e4c-4a7b-8c9f-2b3d4e5f6a71"
                  Name="Deny MSBuild.exe (Visual Studio) for standard users"
                  Description="Blocks MSBuild from Visual Studio install paths (GAP-008)"
                  UserOrGroupSid="S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\Microsoft Visual Studio\*\*\MSBuild\*\Bin\MSBuild.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

Structure notes:
- `UserOrGroupSid` is the SID of a dedicated group, `MEDDEFENSE\WS-Standard-Users`, that holds the non-admin workstation accounts. Replace the `XXXX` placeholder with the group's real SID. Each Id must be a new GUID.
- The group is the deny target because AppLocker Deny overrides Allow. Denying Everyone would also block administrators, and the Windows-folder default allow rule would still allow MSBuild for them unless it is removed. Keep membership current: a standard user who is not in the group is not blocked.
- Keep AppLocker's default allow rules for `%WINDIR%\*` and `%PROGRAMFILES%\*`, or Windows components will fail to start.
- AppLocker requires the Application Identity service (`AppIDSvc`) to be running.

**Developer impact:** The clean baseline shows developers building from `C:\src` on WST-WS-042 (kpatel) and WST-WS-051 (rcorgan). Non-admin developers will lose MSBuild until they are added to the CI/CD group or moved to the build server. Decide that before enforcement.

**Validation:** `Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" -User "MEDDEFENSE\<standard test user>"` returns `Denied`.

## HRD-003: Conditional Access for Sign-in from a New Geography

**Closes:** GAP-003 (risk signals suppressed by the 'compliant device' rule), GAP-004 (no geo/IP block for 45.63.9.88, RU), GAP-005 (risk signals not routed to SOC)

**Policy logic:**
1. **Block:** Users: all users, excluding break-glass accounts. Cloud apps: Office 365 and the VPN gateway's registered app. Conditions: Locations include all countries outside the MEDDEFENSE operating list; grant Block.
2. **Step-up:** Users: all users. Conditions: Sign-in risk is Medium or High, or Unfamiliar sign-in properties is detected. Grant: Require MFA, with no device-compliance exception.
3. **Remove the exception:** Delete the 'compliant device' exclusion from the sign-in risk policy (GAP-003).
4. **SOC routing:** Send Identity Protection risky sign-in alerts to the SOC queue (GAP-005).

**Limit:** A conditional access policy cannot test "country not seen for this account in the prior 30 days" by itself. The closest native signal is Identity Protection's "Unfamiliar sign-in properties" risk, which requires Entra ID P2. The 30-day baseline has to come from that risk detection or a SIEM analytic over the sign-in logs. The VPN session in the incident was an Office 365 session, so the cloud app scope is what matters.

**Validation:** In Entra admin center, Conditional Access > What If, with user = a test account, location = RU, and app = Office 365. Expected result: the Block policy applies.

## HRD-004: Windows Credential Guard

**Closes:** GAP-011 (no LSASS access telemetry while NTLM material for dmarsh was in memory), GAP-012 (RunAsPPL and Credential Guard not enforced on WST-WS-031)

**Configuration:**
- GPO: Computer Configuration > Administrative Templates > System > Device Guard
  - Turn On Virtualization Based Security: Enabled
  - Select Platform Security Level: Secure Boot
  - Credential Guard Configuration: Enabled with UEFI lock
- Equivalent registry values under `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`:
  - `EnableVirtualizationBasedSecurity` = 1
  - `RequirePlatformSecurityFeatures` = 1
  - `LsaCfgFlags` = 1 (UEFI lock)
- Pair with the RunAsPPL value from GAP-012: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` = 1.

**Supported platforms:** Windows 10 and Windows 11 Enterprise and Education, and Windows Server 2016 and later. Hardware must have a 64-bit CPU with virtualization extensions (Intel VT-x or AMD-V), SLAT, UEFI with Secure Boot, and TPM 2.0 recommended. Windows Pro is not a supported edition for enabling Credential Guard. Confirm the edition matrix in current Microsoft documentation before rollout, because support changes between releases.

**Effect:** Moves NTLM hashes and Kerberos TGTs into an isolated container that lsass in the normal kernel cannot read. Enables the GAP-012 check and removes the material that enabled the WS-017 logon.

**Validation:** `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning` contains `1`.
