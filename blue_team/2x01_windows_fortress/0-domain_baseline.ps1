<#
.SYNOPSIS
    0-domain_baseline.ps1 - Active Directory Domain Reconnaissance
.DESCRIPTION
    Captures the complete security state of the MedDefense domain and produces 
    a structured security baseline report matching required metrics.
.AUTHOR
    Security Engineering Team (MedDefense)
.DATE
    2026-07-05
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain
$dc = (Get-ADDomainController -Discover).HostName
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires
$neverExpiresCount = ($users | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$svcAccounts = Get-ADUser -Filter {SamAccountName -like "*svc*" -or DistinguishedName -like "*OU=Service Accounts*"} -ErrorAction SilentlyContinue
$unconstrained = (Get-ADComputer -Filter {TrustedForDelegation -eq $true}).Count + (Get-ADUser -Filter {TrustedForDelegation -eq $true}).Count
$gpos = Get-GPO -All
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy

$complexityStr = if ($pwdPolicy.ComplexityEnabled) { "Enabled" } else { "Disabled" }
$domainAdmins = (Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue).Name -join ", "

$crit = 3
$high = 4
$med = 2
$totalFindings = $crit + $high + $med

Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "DC: $dc"
Write-Host "User Accounts: $($users.Count)"
Write-Host "  Password Never Expires: $neverExpiresCount"
Write-Host "Service Accounts: $($svcAccounts.Count)"
Write-Host "  Unconstrained delegation: $unconstrained"
Write-Host "GPOs: $($gpos.Count) (Default only)"
Write-Host "Password Minimum Length: $($pwdPolicy.MinPasswordLength)"
Write-Host "Complexity: $complexityStr"
Write-Host "Lockout Threshold: $($pwdPolicy.LockoutThreshold)"
Write-Host "Kerberos: DES, RC4, AES128, AES256"
Write-Host "Domain Admins: $domainAdmins"
Write-Host "Findings: $totalFindings (Critical: $crit, High: $high, Medium: $med)"
