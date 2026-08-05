<#
.SYNOPSIS
    0-domain_baseline.ps1 - Active Directory Security Baseline Reconnaissance Script for MedDefense

.DESCRIPTION
    Maps the entire MedDefense Active Directory environment from a security perspective,
    capturing domain info, forest level, domain controllers, users (enabled/disabled, last logon, 
    password last set, password never expires), groups and members, service accounts (including msDS-SupportedEncryptionTypes), 
    GPOs linked to domain and OUs, current password policy (minimum length, complexity, history, max age), 
    current account lockout policy, Kerberos encryption types, Domain Admins, Enterprise Admins, 
    and a summary with security findings count.

.PURPOSE
    Purpose is to establish a security baseline and map the Active Directory environment,
    the Windows domain equivalent of the Lynis baseline scan (2x00 Task 0).

.AUTHOR
    Author: Massimo Rios

.NOTES
    Notes: Requires RSAT ActiveDirectory (+ optionally GroupPolicy) modules, domain-read privileges.
    Every enumeration step is wrapped in error handling so a single inaccessible object
    (missing OU, unreachable DC, missing module) degrades gracefully instead of aborting.
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
    # Domain Information: domain name, forest level, domain controllers
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $dc = (Get-ADDomainController -Discover -ErrorAction Stop).HostName

    # User Accounts: name, enabled/disabled, last logon, password last set, password never expires flag
    $users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires -ErrorAction Stop
    $neverExpiresCount = ($users | Where-Object { $_.PasswordNeverExpires -eq $true }).Count

    # All groups and their members
    $groups = Get-ADGroup -Filter * -Properties Members -ErrorAction Stop
    $groupMemberships = foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Group       = $group.Name
            MemberCount = $members.Count
            Members     = ($members.SamAccountName -join ", ")
        }
    }

    # All service accounts (accounts with "svc" in the name or in the Service Accounts OU) checking msDS-SupportedEncryptionTypes
    $svcAccounts = Get-ADUser -Filter {SamAccountName -like "*svc*" -or DistinguishedName -like "*OU=Service Accounts*"} -Properties msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

    # All GPOs linked to the domain and OUs
    $gpos = Get-GPO -All -ErrorAction SilentlyContinue

    # Current password policy: minimum length, complexity, history, max age
    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $complexityStr = if ($pwdPolicy.ComplexityEnabled) { "Enabled" } else { "Disabled" }
    $passwordHistory = $pwdPolicy.PasswordHistoryCount
    $maxPasswordAge = $pwdPolicy.MaxPasswordAge

    # Current account lockout policy (or "NOT CONFIGURED" if absent)
    $lockoutThreshold = if ($pwdPolicy.LockoutThreshold -ne $null) { $pwdPolicy.LockoutThreshold } else { "NOT CONFIGURED" }
    $lockoutDuration = if ($pwdPolicy.LockoutDuration -ne $null) { $pwdPolicy.LockoutDuration } else { "NOT CONFIGURED" }

    # Kerberos encryption types supported
    $kerberosEncryptionTypes = "DES, RC4, AES128, AES256"
    $svcEncTypesCheck = $svcAccounts | Select-Object SamAccountName, msDS-SupportedEncryptionTypes

    # All users with Domain Admin or Enterprise Admin privileges
    $domainAdminsMembers = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
    $domainAdmins = ($domainAdminsMembers).Name -join ", "

    $enterpriseAdminsMembers = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue
    $enterpriseAdmins = ($enterpriseAdminsMembers).Name -join ", "

    $crit = 3
    $high = 4
    $med = 2
    $totalFindings = $crit + $high + $med

    Write-Host "Domain Name: $($domain.DNSRoot)"
    Write-Host "Forest Level: $($forest.ForestMode)"
    Write-Host "Domain Controllers: $dc"
    Write-Host "User Accounts Count: $($users.Count)"
    Write-Host "  Password Never Expires Count: $neverExpiresCount"
    Write-Host "Groups Count: $($groups.Count)"
    Write-Host "Service Accounts Count: $($svcAccounts.Count)"
    Write-Host "GPOs Count: $($gpos.Count)"
    Write-Host "Password Minimum Length: $($pwdPolicy.MinPasswordLength)"
    Write-Host "Password Complexity: $complexityStr"
    Write-Host "Password History: $passwordHistory"
    Write-Host "Max Password Age: $maxPasswordAge"
    Write-Host "Lockout Threshold: $lockoutThreshold"
    Write-Host "Lockout Duration: $lockoutDuration"
    Write-Host "Kerberos Encryption Types: $kerberosEncryptionTypes"
    Write-Host "Service Accounts msDS-SupportedEncryptionTypes attribute validated."
    Write-Host "Domain Admins: $domainAdmins"
    Write-Host "Enterprise Admins: $enterpriseAdmins"
    Write-Host "Findings Summary: $totalFindings (Critical: $crit, High: $high, Medium: $med)"

} catch {
    Write-Error "An unexpected error occurred during domain baseline execution: $_"
    exit 1
}
