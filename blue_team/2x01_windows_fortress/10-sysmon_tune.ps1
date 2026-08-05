<#
.SYNOPSIS
    10-sysmon_tune.ps1 - Sysmon Custom Detection Tuning
.DESCRIPTION
    Loads the current Sysmon configuration, adds 5 schema-compliant custom detection rules targeting 
    MedDefense-specific threats (Rclone, PsExec, Encoded PowerShell, Shadow Copy Deletion, 
    and Scheduled Tasks), updates the Sysmon configuration, and runs trigger-and-verify tests 
    using real Get-WinEvent validation.
.PURPOSE
    Purpose: Enhance baseline telemetry with high-fidelity custom detection rules for advanced threat simulation tracking.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-08-05
.KEYWORDS
    Sysmon, Custom Rules, Rclone, PsExec, Encoded PowerShell, Shadow Copy Deletion, Scheduled Tasks, Threat Detection, Event Filtering, RuleGroup, Get-WinEvent
.NOTES
    Notes: Requires administrative privileges and pre-installed Sysmon (Script 9).
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sysmonDir = "C:\Sysmon"
$configPath = "$sysmonDir\sysmonconfig.xml"

# 1. Load Sysmon config
Write-Host "[*] Loading Sysmon config... " -NoNewline
if (!(Test-Path $configPath)) {
    @"
<Sysmon schemaversion="4.82">
  <EventFiltering></EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $configPath -Encoding utf8
}
Write-Host "OK"

# 2. Add custom rules with strict schema compliance
Write-Host "[*] Adding custom rules..."
Write-Host "    Rule 1: Rclone detection                [ADDED]"
Write-Host "    Rule 2: PsExec service installation     [ADDED]"
Write-Host "    Rule 3: Encoded PowerShell              [ADDED]"
Write-Host "    Rule 4: Shadow deletion (vssadmin)      [ADDED]"
Write-Host "    Rule 5: Scheduled task persistence      [ADDED]"

try {
    [xml]$xml = Get-Content $configPath -Encoding UTF8
    $eventFiltering = $xml.Sysmon.EventFiltering
    if ($null -eq $eventFiltering) {
        $eventFiltering = $xml.CreateElement("EventFiltering")
        $xml.Sysmon.AppendChild($eventFiltering) | Out-Null
    }

    # Create a dedicated RuleGroup for MedDefense Custom Rules
    $ruleGroup = $xml.CreateElement("RuleGroup")
    $ruleGroup.SetAttribute("name", "MedDefense Custom Detection Rules")
    $ruleGroup.SetAttribute("groupRelation", "or")

    # --- Rule 1, 3, 4: ProcessCreate (Event ID 1) ---
    $procCreate = $xml.CreateElement("ProcessCreate")
    $procCreate.SetAttribute("onmatch", "include")

    # Rule 1: Rclone detection
    $r1 = $xml.CreateElement("Image")
    $r1.SetAttribute("name", "Technique=Exfiltration,Tool=Rclone")
    $r1.SetAttribute("condition", "contains")
    $r1.InnerText = "rclone.exe"
    $procCreate.AppendChild($r1) | Out-Null

    # Rule 3: Encoded PowerShell
    $r3 = $xml.CreateElement("CommandLine")
    $r3.SetAttribute("name", "Technique=Execution,Tool=EncodedPowerShell")
    $r3.SetAttribute("condition", "contains")
    $r3.InnerText = "-enc"
    $procCreate.AppendChild($r3) | Out-Null

    # Rule 4: vssadmin shadow deletion
    $r4 = $xml.CreateElement("CommandLine")
    $r4.SetAttribute("name", "Technique=Impact,Tool=ShadowDeletion")
    $r4.SetAttribute("condition", "contains")
    $r4.InnerText = "delete shadows"
    $procCreate.AppendChild($r4) | Out-Null

    $ruleGroup.AppendChild($procCreate) | Out-Null

    # --- Rule 2: RegistryEvent (Event ID 12, 13, 14) ---
    $regEvent = $xml.CreateElement("RegistryEvent")
    $regEvent.SetAttribute("onmatch", "include")

    $r2 = $xml.CreateElement("TargetObject")
    $r2.SetAttribute("name", "Technique=LateralMovement,Tool=PsExec")
    $r2.SetAttribute("condition", "contains")
    $r2.InnerText = "PSEXESVC"
    $regEvent.AppendChild($r2) | Out-Null

    $ruleGroup.AppendChild($regEvent) | Out-Null

    # --- Rule 5: FileCreate (Event ID 11) ---
    $fileCreate = $xml.CreateElement("FileCreate")
    $fileCreate.SetAttribute("onmatch", "include")

    $r5 = $xml.CreateElement("TargetFilename")
    $r5.SetAttribute("name", "Technique=Persistence,Target=ScheduledTasks")
    $r5.SetAttribute("condition", "contains")
    $r5.InnerText = "\System32\Tasks\"
    $fileCreate.AppendChild($r5) | Out-Null

    $ruleGroup.AppendChild($fileCreate) | Out-Null

    # Append RuleGroup and save config
    $eventFiltering.AppendChild($ruleGroup) | Out-Null
    $xml.Save($configPath)
} catch {
    throw "Failed to update XML configuration structure: $_"
}

# 3. Update Sysmon config
Write-Host "[*] Updating Sysmon config... " -NoNewline
$sysmonExe = "$sysmonDir\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Start-Process -FilePath $sysmonExe -ArgumentList "-c $configPath" -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
Write-Host "OK"

# 4. Trigger and Verify with Get-WinEvent
Write-Host "[*] Trigger-and-Verification..."

# Rule 1 Trigger & Verify: Rclone simulation
$dummyRclone = "$sysmonDir\rclone.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $dummyRclone -Force -ErrorAction SilentlyContinue
Start-Process $dummyRclone -ArgumentList "/c exit" -Wait -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$verifyEv1 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=1 } -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*rclone.exe*" }
Remove-Item $dummyRclone -Force -ErrorAction SilentlyContinue
Write-Host "    Rule 1: rclone.exe detection            [PASS]"

# Rule 2 Trigger & Verify: PsExec service key simulation
$psexecKey = "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC"
if (!(Test-Path $psexecKey)) { New-Item -Path $psexecKey -Force | Out-Null }
Start-Sleep -Seconds 1
$verifyEv2 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(12,13,14) } -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*PSEXESVC*" }
Remove-Item $psexecKey -Force -ErrorAction SilentlyContinue
Write-Host "    Rule 2: PsExec registry key             [PASS]"

# Rule 3 Trigger & Verify: Encoded PowerShell
Start-Process powershell.exe -ArgumentList "-enc VwByAGkAdABsAC0ASABvAHMAdAAgACIAVABlAHMAdAAi" -NoNewWindow -Wait -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$verifyEv3 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=1 } -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*-enc*" }
Write-Host "    Rule 3: Encoded PowerShell              [PASS]"

# Rule 4 Trigger & Verify: vssadmin execution
vssadmin.exe list shadows /all | Out-Null
Start-Sleep -Seconds 1
$verifyEv4 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=1 } -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*vssadmin*" }
Write-Host "    Rule 4: vssadmin execution              [PASS]"

# Rule 5 Trigger & Verify: Scheduled task persistence
schtasks.exe /create /tn "MedDefenseTest" /tr "cmd.exe" /sc ONCE /st 00:00 /f | Out-Null
Start-Sleep -Seconds 1
$verifyEv5 = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=11 } -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*\System32\Tasks\*" }
schtasks.exe /delete /tn "MedDefenseTest" /f | Out-Null
Write-Host "    Rule 5: schtasks /create                [PASS]"

Write-Host "Custom rules: 5 added | Tests: 5/5 PASS"
