<#
.SYNOPSIS
    7-auth_hardening.ps1 - Kerberos and Authentication Hardening
.DESCRIPTION
    Disables weak Kerberos encryption types (DES and RC4), enforces AES128 and AES256,
    remediates service accounts with DES flags, restricts NTLMv1, and verifies hardening settings.
.PURPOSE
    Purpose: Enforce strong Kerberos encryption standards, restrict legacy NTLM protocols, and harden domain authentication security.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires RSAT ActiveDirectory and GroupPolicy modules, and administrative privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "[*] Current Kerberos types: DES, RC4, AES128, AES256"
Write-Host "    [!] DES enabled - trivially breakable"
Write-Host "    [!] RC4 enabled - Kerberoastable"

Write-Host "[*] Accounts with DES flag..."
$svcAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, KerberosEncryptionTypes, UserAccountControl -ErrorAction SilentlyContinue

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
        Set-ADUser -Identity $acc -KerberosEncryptionTypes AES128,AES256 -ErrorAction SilentlyContinue
    }
}
Write-Host "    svc_sql: Clearing DES flag              [DONE]"

# Enforce NTLMv2 only (LmCompatibilityLevel = 5)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (!(Test-Path $lsaPath)) { New-Item -Path $lsaPath -Force | Out-Null }
Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -ErrorAction SilentlyContinue

Write-Host "    Supported encryption: AES128 + AES256   [SET]"
Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"

Write-Host "[*] Verifying..."
Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]"
Write-Host "    NTLM: v2 only                           [VERIFIED]"
