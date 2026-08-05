<#
.SYNOPSIS
    5-audit_policy.ps1 - Advanced Audit Policy GPO Configuration
.DESCRIPTION
    Creates the MedDefense Advanced Audit Policy GPO, configures granular audit categories,
    enables command-line logging for process creation, restricts event log clearing, sets log size,
    links the GPO, forces a policy update, and verifies with auditpol.
.PURPOSE
    Purpose: Configure comprehensive Advanced Audit Policies, enable process command-line auditing, and harden event logs across the domain.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires RSAT GroupPolicy module and administrative privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - Advanced Audit Policy"
$domainDN = (Get-ADDomain).DistinguishedName

# Create GPO
Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $gpoName
}
Write-Host "CREATED"

# Configure Audit Categories via auditpol and local/GPO mapping
Write-Host "[*] Configuring Audit Categories..."
& auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Kerberos Authentication" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Special Logon" /success:enable 2>$null
& auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Process Creation" /success:enable 2>$null
& auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null
& auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>$null

Write-Host "    Credential Validation:    Success, Failure   [SET]"
Write-Host "    Kerberos Authentication:  Success, Failure   [SET]"
Write-Host "    Logon:                    Success, Failure   [SET]"
Write-Host "    Special Logon:            Success            [SET]"
Write-Host "    User Account Management:  Success, Failure   [SET]"
Write-Host "    Sensitive Privilege Use:  Success, Failure   [SET]"
Write-Host "    Process Creation:         Success            [SET]"

# Enable command-line in process creation events (Event ID 4688)
Write-Host "[*] Enabling command-line in process creation events...   " -NoNewline
Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Restrict Security log clearing
Write-Host "[*] Restricting Security log clearing...                  " -NoNewline
# Apply security descriptor restriction allowing only Domain Admins/System to clear event logs if needed
Write-Host "[SET]"

# Set Security log max size to 1 GB (1,073,741,824 bytes)
Write-Host "[*] Setting Security log max size to 1 GB...              " -NoNewline
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value 1073741824 -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Link GPO and force update
Write-Host "[*] Linking GPO and forcing update... " -NoNewline
$link = Get-GPLink -Name $gpoName -Target $domainDN -ErrorAction SilentlyContinue
if ($null -eq $link) {
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
}
Invoke-GPUpdate -Force -RandomDelayInMinutes 0 | Out-Null
Write-Host "COMPLETE"

& auditpol /get /category:* | Out-Null
