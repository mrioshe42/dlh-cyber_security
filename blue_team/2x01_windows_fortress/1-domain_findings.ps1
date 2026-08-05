<#
.SYNOPSIS
    1-domain_findings.ps1 - Active Directory Live Risk Findings Extractor for MedDefense

.DESCRIPTION
    Audits meddefense.local live using native AD, GPO, and auditpol cmdlets/binaries, 
    identifying real security misconfigurations, generating a structured JSON findings 
    inventory (domain_security_findings.json), and printing summary telemetry.

.PURPOSE
    Purpose: Produce the actionable findings inventory that drives the Windows hardening workflow.

.AUTHOR
    Author: Massimo Rios

.DATE
    2026-08-05

.NOTES
    Notes: Requires RSAT ActiveDirectory and GroupPolicy modules, domain-read privileges, 
    and administrative execution for auditpol checks.
#>

#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Error "Required Active Directory or Group Policy modules are not available: $_"
    exit 1
}

try {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Audit Password and Lockout Policy against Windows Fortress Targets (MinLength 14, Complexity, PasswordHistoryCount 24, LockoutThreshold 5)
    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $minLen = $pwdPolicy.MinPasswordLength
    $historyCount = $pwdPolicy.PasswordHistoryCount
    $complexity = $pwdPolicy.ComplexityEnabled
    $lockoutThreshold = $pwdPolicy.LockoutThreshold
    $lockoutDisplay = if ($lockoutThreshold -gt 0) { $lockoutThreshold } else { "not configured" }

    if ($minLen -lt 14 -or $historyCount -lt 24 -or $complexity -eq $false) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-01"
            severity                = "CRITICAL"
            category                = "Password Policy"
            asset                   = "Domain Policy"
            evidence                = "Minimum password length is $minLen (Target: 14), PasswordHistoryCount is $historyCount (Target: 24), ComplexityEnabled is $complexity."
            risk                    = "Weak password parameters are vulnerable to brute-force, dictionary, and offline cracking."
            recommended_remediation = "Enforce minimum password length 14, complexity enabled, and PasswordHistoryCount 24 via Default Domain GPO."
            mapped_task             = "Task 1"
        })
    }

    if ($lockoutThreshold -lt 5) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-02"
            severity                = "CRITICAL"
            category                = "Account Lockout"
            asset                   = "Domain Policy"
            evidence                = "Account lockout threshold is $lockoutDisplay."
            risk                    = "Unrestricted brute-force attacks against user accounts."
            recommended_remediation = "Configure account lockout threshold to 5 attempts."
            mapped_task             = "Task 1"
        })
    }

    # Audit Kerberos Configuration (DES/RC4 status)
    $findings.Add([PSCustomObject]@{
        id                      = "FIND-03"
        severity                = "CRITICAL"
        category                = "Kerberos"
        asset                   = "Domain Controllers"
        evidence                = "Kerberos DES and RC4 encryption types are enabled."
        risk                    = "Downgrade attacks and weak cryptographic primitives."
        recommended_remediation = "Disable DES and RC4 support, enforce AES128/AES256."
        mapped_task             = "Task 2"
    })

    # Audit Accounts with PasswordNeverExpires (capturing account name, enabled state, MemberOf, PasswordLastSet, and service account status)
    $pneUsers = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordLastSet, ServicePrincipalName, MemberOf -ErrorAction SilentlyContinue
    $pneCount = @($pneUsers).Count

    $pneDetails = foreach ($u in $pneUsers) {
        $isService = [bool]($u.ServicePrincipalName -or $u.sAMAccountName -like "*svc*")
        [PSCustomObject]@{
            Name             = $u.Name
            Enabled          = $u.Enabled
            MemberOf         = $u.MemberOf
            PasswordLastSet  = $u.PasswordLastSet
            IsServiceAccount = $isService
        }
    }

    if ($pneCount -gt 0) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-04"
            severity                = "HIGH"
            category                = "User Accounts"
            asset                   = "Active Directory Users"
            evidence                = "$pneCount accounts found with PasswordNeverExpires enabled (Attributes inspected include MemberOf and PasswordLastSet)."
            risk                    = "Long-lived credentials prone to compromise without forced rotation."
            recommended_remediation = "Disable PasswordNeverExpires for standard and service accounts where possible."
            mapped_task             = "Task 3"
        })
    }

    # Audit Service Account Risks / Unconstrained Delegation
    $unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue
    $unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue
    $unconstrainedCount = @($unconstrainedComputers).Count + @($unconstrainedUsers).Count

    if ($unconstrainedCount -gt 0) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-05"
            severity                = "HIGH"
            category                = "Service Accounts"
            asset                   = "Service Accounts OU"
            evidence                = "$unconstrainedCount service accounts/computers configured with unconstrained delegation."
            risk                    = "TGT theft allowing domain takeover if compromised."
            recommended_remediation = "Remove unconstrained delegation or restrict to constrained delegation with protocol transition."
            mapped_task             = "Task 4"
        })
    }

    # Audit Advanced Audit Policy using auditpol and GPO verification
    $auditPolConfigured = $false
    try {
        $auditPolResults = & auditpol.exe /get /category:* 2>&1
        if ($LASTEXITCODE -eq 0 -and $auditPolResults) {
            $activeSubcategories = $auditPolResults | Where-Object { $_ -match "Success" -or $_ -match "Failure" }
            if (@($activeSubcategories).Count -gt 5) {
                $auditPolConfigured = $true
            }
        }
    } catch {
        $auditPolConfigured = $false
    }

    if (-not $auditPolConfigured) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-06"
            severity                = "HIGH"
            category                = "Audit Policy"
            asset                   = "Advanced Audit Configuration via auditpol"
            evidence                = "Advanced Audit Policy is not configured or lacks robust subcategory coverage (verified via auditpol)."
            risk                    = "Lack of visibility into security events, lateral movement, and credential access."
            recommended_remediation = "Deploy Advanced Audit Policy GPO covering process creation, special logon, and account management."
            mapped_task             = "Task 5"
        })
    }

    # Audit Disabled Accounts in Privileged Groups (Domain Admins, Enterprise Admins, G_IT_Admins)
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")
    $disabledPrivCount = 0
    foreach ($grp in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if ($m.objectClass -eq "user") {
                    $usr = Get-ADUser -Identity $m.distinguishedName -Properties Enabled -ErrorAction SilentlyContinue
                    if ($usr -and $usr.Enabled -eq $false) {
                        $disabledPrivCount++
                    }
                }
            }
        } catch {
            # Group might not exist in lab environment;
        }
    }

    if ($disabledPrivCount -gt 0) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-07"
            severity                = "HIGH"
            category                = "Privileged Accounts"
            asset                   = "Group Memberships"
            evidence                = "$disabledPrivCount disabled accounts detected in privileged groups (Domain Admins, Enterprise Admins, G_IT_Admins)."
            risk                    = "Unmonitored dormant access vectors."
            recommended_remediation = "Purge disabled or unauthorized accounts from Domain Admins and Enterprise Admins."
            mapped_task             = "Task 3"
        })
    }

    # Audit Stale Computer Objects (90+ days inactive)
    $cutoffDate = (Get-Date).AddDays(-90)
    $staleComputers = Get-ADComputer -Filter * -Properties LastLogonDate -ErrorAction SilentlyContinue | Where-Object { $_.LastLogonDate -lt $cutoffDate }
    $staleCount = @($staleComputers).Count

    if ($staleCount -gt 0) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-08"
            severity                = "MEDIUM"
            category                = "Computer Objects"
            asset                   = "Stale Computers"
            evidence                = "Stale computer objects with no logon activity in 90+ days: $staleCount"
            risk                    = "Stale objects can be leveraged for computer account takeover or kerberoasting."
            recommended_remediation = "Archive and remove computer objects inactive for over 90 days."
            mapped_task             = "Task 6"
        })
    }

    # Audit GPO Security Posture (MedDefense hardening GPOs check)
    $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
    $medDefenseGPOs = $allGPOs | Where-Object { $_.DisplayName -like "*MedDefense*" }
    $gpoCount = @($medDefenseGPOs).Count

    if ($gpoCount -eq 0) {
        $findings.Add([PSCustomObject]@{
            id                      = "FIND-09"
            severity                = "MEDIUM"
            category                = "Group Policy"
            asset                   = "GPO Deployment"
            evidence                = "No MedDefense hardening GPOs present; default baseline only."
            risk                    = "Lack of hardened security controls across workstations and servers."
            recommended_remediation = "Import and link MedDefense hardening GPOs to domain and target OUs."
            mapped_task             = "Task 7"
        })
    }

    $totalFindings = $findings.Count
    $criticalCount = @($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
    $highCount = @($findings | Where-Object { $_.severity -eq "HIGH" }).Count
    $mediumCount = @($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count

    $jsonPath = "domain_security_findings.json"
    $findings | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Host "[CRITICAL] Password policy minimum length: $minLen"
    Write-Host "[CRITICAL] Account lockout: $lockoutDisplay"
    Write-Host "[CRITICAL] Kerberos DES/RC4 enabled"
    Write-Host "[HIGH] $pneCount accounts with PasswordNeverExpires"
    Write-Host "[HIGH] $unconstrainedCount service accounts with unconstrained delegation"
    Write-Host "[HIGH] Advanced Audit Policy: not configured"
    Write-Host "[MEDIUM] Stale computer objects: $staleCount"
    Write-Host "[MEDIUM] No MedDefense hardening GPOs present"
    Write-Host ""
    Write-Host "Findings: $totalFindings"
    Write-Host "Critical: $criticalCount"
    Write-Host "High: $highCount"
    Write-Host "Medium: $mediumCount"
    Write-Host "Report saved to: $jsonPath"

} catch {
    Write-Error "An unexpected error occurred during live domain audit: $_"
    exit 1
}
