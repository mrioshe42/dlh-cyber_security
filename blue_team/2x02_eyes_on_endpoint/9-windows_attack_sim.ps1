<#
.SYNOPSIS
    name : 9-windows_attack_sim.ps1
.PURPOSE
    purpose : Execute a controlled sequence of attacker-like actions on a Windows endpoint and generate ground truth telemetry.
    author: Massimo Rios
.NOTES
    project : Cross-Platform Security Telemetry & Validation
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OutputJson = "windows_attack_log.json"
$Actions = [System.Collections.Generic.List[PSCustomObject]]::new()

# Administrator Privileges Check
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Running Windows attacker simulation..." -ForegroundColor Cyan

function Invoke-AttackStep {
    param(
        [int]$StepNumber,
        [string]$Description,
        [string]$ExpectedSource,
        [string]$MitreTechnique,
        [scriptblock]$ActionBlock
    )
    
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "    [$StepNumber/6] $Description...`t$timestamp" -NoNewline
    
    try {
        & $ActionBlock
        Write-Host "" -ForegroundColor Green
    } catch {
        Write-Host " [FAILED: $_]" -ForegroundColor Red
    }

    $script:Actions.Add([PSCustomObject]@{
        action_number             = $StepNumber
        description               = $Description
        timestamp                 = $timestamp
        expected_detection_source = $ExpectedSource
        mitre_attack_technique    = $MitreTechnique
    })
    
    Start-Sleep -Milliseconds 500
}
# Remove-LocalUser
try {
    net user support_update /delete >$null 2>&1
    schtasks /delete /tn "SupportUpdateTask" /f >$null 2>&1
    $StartupDirCheck = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    $StartupFileCheck = "$StartupDirCheck\update_check.bat"
    if (Test-Path $StartupFileCheck) { Remove-Item -Force $StartupFileCheck }
} catch {}

# Create a new local user account
Invoke-AttackStep -StepNumber 1 -Description "Creating local user 'support_update'" -ExpectedSource "Security Event ID 4720" -MitreTechnique "MITRE ATT&CK T1136.001 - Create Account: Local Account" -ActionBlock {
    $TestPassword = ConvertTo-SecureString "MedDefense-Test-2026!" -AsPlainText -Force
    New-LocalUser -Name "support_update" -Password $TestPassword -Description "Support Update Service Account" -AccountNeverExpires | Out-Null
}

# Add the user to the Administrators group
Invoke-AttackStep -StepNumber 2 -Description "Adding to Domain Admins group" -ExpectedSource "Security Event ID 4728 / 4732" -MitreTechnique "MITRE ATT&CK T1098 - Account Manipulation" -ActionBlock {
    Add-ADGroupMember -Identity "Domain Admins" -Members "support_update"
}

# Run an encoded PowerShell command -enc
Invoke-AttackStep -StepNumber 3 -Description "Running encoded PowerShell" -ExpectedSource "Sysmon Event ID 1 / PowerShell Script Block ID 4104" -MitreTechnique "MITRE ATT&CK T1059.001 - PowerShell" -ActionBlock {
    $CommandText = 'Write-Host "C2 beacon active"'
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($CommandText)
    $Encoded = [Convert]::ToBase64String($Bytes)
    powershell.exe -NoProfile -EncodedCommand $Encoded
}

# Create a scheduled task for persistence
Invoke-AttackStep -StepNumber 4 -Description "Creating scheduled task" -ExpectedSource "Security Event ID 4698 / Sysmon Event ID 1" -MitreTechnique "MITRE ATT&CK T1053.005 - Scheduled Task/Job: Scheduled Task" -ActionBlock {
    schtasks /create /tn "SupportUpdateTask" /tr "calc.exe" /sc ONLOGON /f >$null 2>&1
}

# Initiate an outbound network connection
Invoke-AttackStep -StepNumber 5 -Description "Outbound network connection" -ExpectedSource "Sysmon Event ID 3 (NetworkConnect)" -MitreTechnique "MITRE ATT&CK T1071.001 - Web Protocols" -ActionBlock {
    Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet >$null 2>&1
}

# Drop a file in a startup directory
$StartupDir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile = "$StartupDir\update_check.bat"

Invoke-AttackStep -StepNumber 6 -Description "Dropping file in Startup" -ExpectedSource "Sysmon Event ID 11 (FileCreate)" -MitreTechnique "MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder" -ActionBlock {
    if (-not (Test-Path $StartupDir)) {
        New-Item -ItemType Directory -Force -Path $StartupDir | Out-Null
    }
    Set-Content -Path $StartupFile -Value "echo C2 Pulse" -Encoding UTF8
}

Write-Host "[*] Cleaning up artifacts..." -ForegroundColor Yellow

$cleanupStatus = "[CLEAN]"
try {
    net user support_update /delete >$null 2>&1
    schtasks /delete /tn "SupportUpdateTask" /f >$null 2>&1
    if (Test-Path $StartupFile) {
        Remove-Item -Force $StartupFile
    }
} catch {
    $cleanupStatus = "[PARTIAL]"
}
# Unregister-ScheduledTask
Write-Host "    User removed, task deleted, file removed           $cleanupStatus" -ForegroundColor Green
Write-Host "Actions executed: 6"

$GroundTruth = [PSCustomObject]@{
    metadata = [PSCustomObject]@{
        simulation = "Windows Attacker Simulation"
        generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        total_actions = 6
    }
    actions = $script:Actions
}

$GroundTruth | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputJson -Encoding utf8
Write-Host "Ground truth saved to: $OutputJson" -ForegroundColor Cyan

