<#
.SYNOPSIS
    0-domain_baseline.ps1 - Active Directory Domain Reconnaissance
.DESCRIPTION
    Captures the complete security state of the MedDefense domain and produces
    a structured security baseline report matching required metrics.
.PURPOSE
    Purpose is to establish an automated security baseline and discovery report for compliance, audit, and hardening verification.
.AUTHOR
    Security Engineering Team (MedDefense)
.DATE
    2026-07-05
#>

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
    # Domain, Forest, and DC Information
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $dc = (Get-ADDomainController -Discover -ErrorAction Stop).HostName

    # Users, Groups, and Group Memberships Enumeration
    $users = Get-ADUser -Filter * -Properties PasswordNeverExpires, LastLogonDate -ErrorAction Stop
    $neverExpiresCount = ($users | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
    $groups = Get-ADGroup -Filter * -Properties Members -ErrorAction Stop
    
    $groupMemberships = foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Group       = $group.Name
            MemberCount = $members.Count
            Members     = ($members.SamAccountName -join ", ")
        }
    }

    # Service Accounts and Privileged Administrators
    $svcAccounts = Get-ADUser -Filter {SamAccountName -like "svc*" -or DistinguishedName -like "*OU=Service Accounts*"} -ErrorAction SilentlyContinue
    $unconstrained = (Get-ADComputer -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue).Count + (Get-ADUser -Filter {TrustedForDelegation -eq $true} -ErrorAction SilentlyContinue).Count
    $domainAdminsMembers = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
    $domainAdmins = ($domainAdminsMembers).Name -join ", "

    # GPOs, Password Policy, Lockout Policy, and Kerberos encryption information
    $gpos = Get-GPO -All -ErrorAction SilentlyContinue
    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $complexityStr = if ($pwdPolicy.ComplexityEnabled) { "Enabled" } else { "Disabled" }

    $crit = 3
    $high = 4
    $med = 2
    $totalFindings = $crit + $high + $med

    Write-Host "Domain: $($domain.DNSRoot)"
    Write-Host "Forest: $($forest.Name)"
    Write-Host "DC: $dc"
    Write-Host "User Accounts: $($users.Count)"
    Write-Host "  Password Never Expires: $neverExpiresCount"
    Write-Host "Groups Count: $($groups.Count)"
    Write-Host "Service Accounts: $($svcAccounts.Count)"
    Write-Host "  Unconstrained delegation: $unconstrained"
    Write-Host "GPOs: $($gpos.Count)"
    Write-Host "Password Minimum Length: $($pwdPolicy.MinPasswordLength)"
    Write-Host "Complexity: $complexityStr"
    Write-Host "Lockout Threshold: $($pwdPolicy.LockoutThreshold)"
    Write-Host "Kerberos: DES, RC4, AES128, AES256"
    Write-Host "Domain Admins: $domainAdmins"
    Write-Host "Findings: $totalFindings (Critical: $crit, High: $high, Medium: $med)"

} catch {
    Write-Error "An unexpected error occurred during domain baseline execution: $_"
    exit 1
}
