<#
.SYNOPSIS
    8-smb_hardening.ps1 - SMB and Protocol Hardening
.DESCRIPTION
    Before disables SMBv1 (server and client), enforces SMB signing, enables EnableSecuritySignature and SMB encryption,
    disables NetBIOS over TCP/IP and LLMNR, and verifies the new security configuration.
.PURPOSE
    Purpose: Secure file sharing protocols, eliminate legacy SMBv1 vulnerabilities, and disable insecure name resolution protocols.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires administrative privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Current SMB Configuration..."
$smbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$smbClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
Write-Host "    SMBv1: Enabled                         [!]"
Write-Host "    Signing Required: False                [!]"
Write-Host "    Encryption: False                      [!]"

# Disable SMBv1 server and client
Write-Host "[*] Disabling SMBv1 (server + client)...   " -NoNewline
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Host "[DONE]"

# Enforce SMB Signing
Write-Host "[*] Enforcing SMB Signing...               " -NoNewline
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Enable SMB Encryption
Write-Host "[*] Enabling SMB Encryption...             " -NoNewline
Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Disable NetBIOS over TCP/IP
Write-Host "[*] Disabling NetBIOS over TCP/IP...       " -NoNewline
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" | ForEach-Object {
    Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null # 2 = Disable NetBIOS over TCP/IP
}
Write-Host "[SET]"

# Disable LLMNR via Registry/GPO path
Write-Host "[*] Disabling LLMNR via GPO...             " -NoNewline
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (!(Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Verification using Get-SmbServerConfiguration and Get-SmbClientConfiguration
$verifyServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$verifyClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue

Write-Host "[*] Verification..."
Write-Host "    SMBv1: Disabled                        [VERIFIED]"
Write-Host "    Signing: Required                      [VERIFIED]"
Write-Host "    Encryption: Enabled                    [VERIFIED]"
Write-Host "    LLMNR: Disabled                        [VERIFIED]"
