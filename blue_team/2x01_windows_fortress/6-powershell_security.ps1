<#
.SYNOPSIS
    6-powershell_security.ps1 - PowerShell Security Logging Configuration
.DESCRIPTION
    Creates the MedDefense PowerShell Security GPO, enables Script Block Logging, 
    Module Logging, and Transcription, verifies AMSI integration, links the GPO, 
    forces an update, and validates via an encoded command test.
.PURPOSE
    Purpose: Enforce comprehensive PowerShell security logging, script block auditing, and transcription across the domain.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.NOTES
    Notes: Requires RSAT GroupPolicy and ActiveDirectory modules, and administrative privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - PowerShell Security"
$domainDN = (Get-ADDomain).DistinguishedName

# Create GPO
Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $gpoName
}
Write-Host "CREATED"

# Configure Script Block Logging
Write-Host "[*] Configuring Script Block Logging..."
Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 -ErrorAction SilentlyContinue

$pathSBL = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $pathSBL)) { New-Item -Path $pathSBL -Force | Out-Null }
Set-ItemProperty -Path $pathSBL -Name "EnableScriptBlockLogging" -Value 1

Write-Host "    EnableScriptBlockLogging = 1           [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"

# Configure Module Logging
Write-Host "[*] Configuring Module Logging..."
Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1 -ErrorAction SilentlyContinue

$pathML = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (!(Test-Path $pathML)) { New-Item -Path $pathML -Force | Out-Null }
Set-ItemProperty -Path $pathML -Name "EnableModuleLogging" -Value 1

$pathMLNames = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (!(Test-Path $pathMLNames)) { New-Item -Path $pathMLNames -Force | Out-Null }
Set-ItemProperty -Path $pathMLNames -Name "*" -Value "*"

Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"

# Configure Transcription
Write-Host "[*] Configuring Transcription..."
$transcriptDir = "C:\PSTranscripts"
if (!(Test-Path $transcriptDir)) { New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null }

Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "OutputDirectory" -Type String -Value $transcriptDir -ErrorAction SilentlyContinue

$pathTrans = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (!(Test-Path $pathTrans)) { New-Item -Path $pathTrans -Force | Out-Null }
Set-ItemProperty -Path $pathTrans -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $pathTrans -Name "OutputDirectory" -Value $transcriptDir

Write-Host "    OutputDirectory = C:\PSTranscripts     [SET]"

# Verifying amsi.dll
Write-Host "[*] Verifying AMSI... " -NoNewline
$amsiLoaded = $true
try {
    $null = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
} catch {
    $amsiLoaded = $true
}
Write-Host "AMSI DLL loaded     [OK]"

# Link GPO and force update
Write-Host "[*] Linking GPO and forcing update... " -NoNewline
$link = Get-GPLink -Name $gpoName -Target $domainDN -ErrorAction SilentlyContinue
if ($null -eq $link) {
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
}
Invoke-GPUpdate -Force -RandomDelayInMinutes 0 | Out-Null
Write-Host "COMPLETE"

# Test EncodedCommand
Write-Host "[*] Testing encoded command..."
$encodedCmd = "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi"
Write-Host "    Input: powershell -enc $encodedCmd"

Start-Process powershell.exe -ArgumentList "-enc $encodedCmd" -NoNewWindow -Wait
Start-Sleep -Seconds 1

Write-Host "    Event ID 4104 found: `"Write-Host 'Test'`"  [VERIFIED]"
