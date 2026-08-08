<#
.SYNOPSIS
    name : 0-sysmon_validation.ps1
.DESCRIPTION
    Re-engineered validation matrix ensuring deep inspection of Windows Sysmon telemetry across core security event IDs.
.PURPOSE
    purpose : Execute granular runtime assertions on Sysmon event logs to eliminate monitoring blind spots.
.AUTHOR
    author: Massimo Rios
.NOTES
    project : Built for high-fidelity endpoint assurance and compliance checks.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$TelemetryLogChannel = "Microsoft-Windows-Sysmon/Operational"
$AccumulatedPasses = 0

Write-Host "[*] Initializing advanced Sysmon telemetry verification suite..." -ForegroundColor Cyan

function Test-TelemetryCapture {
    param(
        [Parameter(Mandatory=$true)][int]$TargetEventId,
        [Parameter(Mandatory=$true)][string]$ActivityName,
        [Parameter(Mandatory=$true)][scriptblock]$ExecutionBlock,
        [Parameter(Mandatory=$true)][string[]]$ExpectedKeywords,
        [Parameter(Mandatory=$true)][string]$SuccessLogMessage,
        [Parameter(Mandatory=$true)][string]$FailureLogMessage
    )

    Write-Host "    [Executing] Checking vector: $ActivityName (Event ID $TargetEventId)..." -ForegroundColor Yellow
    
    $CheckpointTime = Get-Date

    & $ExecutionBlock
    Start-Sleep -Seconds 2

    # Query event logs via hashtable filter
    $MatchedEvent = Get-WinEvent -FilterHashtable @{
        LogName   = $TelemetryLogChannel
        Id        = $TargetEventId
        StartTime = $CheckpointTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $LogEntry = $_.Message
        $AllMatch = $true
        foreach ($Keyword in $ExpectedKeywords) {
            if ($LogEntry -notlike "*$Keyword*") {
                $AllMatch = $false
                break
            }
        }
        $AllMatch
    } | Select-Object -First 1

    if ($MatchedEvent) {
        Write-Host "          $SuccessLogMessage   [PASS]" -ForegroundColor Green
        $script:AccumulatedPasses++
        return $true
    }
    else {
        Write-Host "          $FailureLogMessage   [FAIL]" -ForegroundColor Red
        return $false
    }
}

# Process Creation (ID 1)
Test-TelemetryCapture `
    -TargetEventId 1 `
    -ActivityName "Process Creation" `
    -ExecutionBlock { Start-Process cmd.exe "/c whoami" -Wait -NoNewWindow } `
    -ExpectedKeywords @("cmd.exe", "whoami") `
    -SuccessLogMessage "cmd.exe /c whoami -> Sysmon EID 1 captured, CommandLine present" `
    -FailureLogMessage "Process creation vector not captured"

# Network Connection (ID 3)
Test-TelemetryCapture `
    -TargetEventId 3 `
    -ActivityName "Network Connection" `
    -ExecutionBlock { Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet | Out-Null } `
    -ExpectedKeywords @("1.1.1.1", "443") `
    -SuccessLogMessage "Outbound TCP -> Sysmon EID 3 captured, DestinationIp / DestinationPort present" `
    -FailureLogMessage "Network telemetry vector not captured"

# File Creation (ID 11)
$ValidationArtifact = "C:\Windows\Temp\sysmon_test_artifact.dat"
Test-TelemetryCapture `
    -TargetEventId 11 `
    -ActivityName "File Creation" `
    -ExecutionBlock { "TelemetryPayloadData" | Out-File $ValidationArtifact } `
    -ExpectedKeywords @("TargetFilename", "sysmon_test_artifact.dat") `
    -SuccessLogMessage "$ValidationArtifact -> Sysmon EID 11 captured" `
    -FailureLogMessage "File creation vector not captured"

# Registry Modification (ID 13)
$RegistryTargetHive = "HKCU:\Software\SysmonValidationKey"
$TargetRegistryValue = "VerificationToken"
Test-TelemetryCapture `
    -TargetEventId 13 `
    -ActivityName "Registry Modification" `
    -ExecutionBlock {
        New-Item $RegistryTargetHive -Force | Out-Null
        Set-ItemProperty $RegistryTargetHive -Name $TargetRegistryValue -Value "Active"
    } `
    -ExpectedKeywords @("SysmonValidationKey", "VerificationToken") `
    -SuccessLogMessage "HKCU Registry Path -> Sysmon EID 13 captured" `
    -FailureLogMessage "Registry mutation vector not captured"

# DNS Query (ID 22)
Test-TelemetryCapture `
    -TargetEventId 22 `
    -ActivityName "DNS Query" `
    -ExecutionBlock { Resolve-DnsName example.com | Out-Null } `
    -ExpectedKeywords @("example.com") `
    -SuccessLogMessage "Resolve-DnsName example.com -> Sysmon EventID 22 captured" `
    -FailureLogMessage "DNS resolution vector not captured"

Write-Host "[*] Purging test artifacts and cleaning state..." -ForegroundColor Cyan
Remove-Item $ValidationArtifact -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $RegistryTargetHive -Name $TargetRegistryValue -ErrorAction SilentlyContinue
Remove-Item $RegistryTargetHive -Recurse -Force -ErrorAction SilentlyContinue

$TotalFailures = 5 - $AccumulatedPasses

Write-Host ""
Write-Host "Actions tested: 5 | Captured: $AccumulatedPasses | Missed: $TotalFailures" -ForegroundColor Cyan
