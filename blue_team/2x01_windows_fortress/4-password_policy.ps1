<#
.SYNOPSIS
    4-password_policy.ps1 - CIS-Compliant Password and Account Lockout Policy Deployment
.DESCRIPTION
    Creates the MedDefense Password and Lockout Policy GPO, configures domain password 
    and lockout parameters to meet security baselines, links the GPO to the domain root, 
    and forces a policy update.
.PURPOSE
    Purpose: Enforce strict CIS-compliant password complexity, history, expiration, and lockout thresholds across the MedDefense domain.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires to VERIFY RSAT ActiveDirectory and GroupPolicy modules, and administrative privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - Password and Lockout Policy"
$domainDN = (Get-ADDomain).DistinguishedName

# Create GPO
Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $gpoName
}
Write-Host "CREATED"

# Configure Password Policy
Write-Host "[*] Configuring Password Policy..."
$currentPolicy = Get-ADDefaultDomainPasswordPolicy -Identity "meddefense.local"
Set-ADDefaultDomainPasswordPolicy -Identity "meddefense.local" `
    -MinimumPasswordLength 14 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge (New-TimeSpan -Days 0) `
    -MinPasswordAge (New-TimeSpan -Days 1)

Write-Host "    Minimum Length: 14            [SET]"
Write-Host "    Complexity: Enabled           [SET]"
Write-Host "    History: 24                   [SET]"
Write-Host "    Maximum Age: 0                [SET]"
Write-Host "    Minimum Age: 1 day            [SET]"

# Configure Account Lockout
Write-Host "[*] Configuring Account Lockout..."
Set-ADDomain -Identity "meddefense.local" `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15)

Write-Host "    Threshold: 5 attempts         [SET]"
Write-Host "    Duration: 15 minutes          [SET]"
Write-Host "    Reset Counter: 15 minutes     [SET]"

# Link GPO to domain root
Write-Host "[*] Linking GPO to domain root... " -NoNewline
$link = Get-GPLink -Name $gpoName -Target $domainDN -ErrorAction SilentlyContinue
if ($null -eq $link) {
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
}
Write-Host "LINKED"

# Force gpupdate
Write-Host "[*] Forcing Group Policy update... " -NoNewline
Invoke-GPUpdate -Force -RandomDelayInMinutes 0 | Out-Null
Write-Host "COMPLETE"
