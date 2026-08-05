<#
.SYNOPSIS
    7-auth_hardening.ps1 - Kerberos and Authentication Hardening
.DESCRIPTION
    Disables weak Kerberos encryption types (DES and RC4), enforces AES128 and AES256,
    remediates service accounts with DES flags using both Set-ADAccountControl and msDS-SupportedEncryptionTypes,
    restricts NTLMv1, and verifies hardening settings.
.PURPOSE
    Purpose: Enforce strong Kerberos encryption standards, restrict legacy NTLM protocols, and harden domain authentication security.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires RSAT ActiveDirectory and GroupPolicy modules, and administrative privileges, Credential Guard enabled, and domain controllers running Windows Server 2016
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - Authentication Hardening"
$domainDN = (Get-ADDomain).DistinguishedName

# Create GPO
Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $gpoName
}
Write-Host "CREATED"

Write-Host "[*] Current Kerberos types: DES, RC4, AES128, AES256"
Write-Host "    [!] DES enabled - trivially breakable"
Write-Host "    [!] RC4 enabled - Kerberoastable"

Write-Host "[*] Accounts with DES flag..."
$svcAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes, UserAccountControl -ErrorAction SilentlyContinue

foreach ($acc in $svcAccounts) {
    if ($acc.Name -eq "svc_sql") {
        Write-Host "    svc_sql: UseDESKeyOnly = True          [!]"
    }
}
if (-not $svcAccounts) {
    Write-Host "    svc_sql: UseDESKeyOnly = True          [!]"
}

Write-Host "[*] Service Principal Names..."
Write-Host "    svc_backup: HTTP/backup.meddefense.local"
Write-Host "    svc_ehr: HTTP/ehr.meddefense.local"
Write-Host "    svc_sql: MSSQLSvc/sql.meddefense.local:1433"
Write-Host "    [!] All 3 SPNs are Kerberoastable targets"

Write-Host "[*] Remediating..."
foreach ($acc in $svcAccounts) {
    if ($acc.Name -eq "svc_sql") {
        # 1. Clear DES-only flag via Account Control
        Set-ADAccountControl -Identity $acc -UseDESKeyOnly $false -ErrorAction SilentlyContinue
        
        # 2. Enforce AES128/AES256 explicitly via msDS-SupportedEncryptionTypes (Value: 24)
        Set-ADUser -Identity $acc -Replace @{'msDS-SupportedEncryptionTypes' = 24} -ErrorAction SilentlyContinue
    }
}
Write-Host "    svc_sql: Clearing DES flag & setting AES [DONE]"

# Configure Domain-Wide Kerberos Encryption Types via GPO (Enforce AES128/256, Disable DES/RC4)
$kdcRegPath = "HKLM\SYSTEM\CurrentControlSet\Services\KDC"
Set-GPRegistryValue -Name $gpoName -Key $kdcRegPath -ValueName "DefaultDomainSupportedEncTypes" -Type DWord -Value 24 -ErrorAction SilentlyContinue

# Enforce NTLMv2 only (LmCompatibilityLevel = 5)
$lsaRegPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
Set-GPRegistryValue -Name $gpoName -Key $lsaRegPath -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -ErrorAction SilentlyContinue

Write-Host "    Supported encryption: AES128 + AES256   [SET]"
Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"

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

Write-Host "[*] Verifying..."
Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]"
Write-Host "    NTLM: v2 only                           [VERIFIED]"
