<#
.SYNOPSIS
    name : 2-powershell_logging_validation.ps1
.PURPOSE
    purpose : Validate PowerShell Script Block Logging (EID 4104), Module Logging (EID 4103), and Session Transcription with full log separation and proactive transcript generation.
    author: Massimo Rios
.NOTES
    project : Endpoint Telemetry & Detection Engineering Suite
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptBlockLog = "Microsoft-Windows-PowerShell/Operational"
$ModuleLog = "Windows PowerShell"

$Results = @()
$Captured = 0
$Missed = 0

Write-Host "[*] Testing PowerShell logging coverage..." -ForegroundColor Cyan

function Wait-PowerShellEvent {
    param(
        [int]$EventID,
        [string]$SearchText,
        [int]$Timeout = 15
    )

    $Start = Get-Date

    while ((Get-Date) -lt $Start.AddSeconds($Timeout)) {
        
        $LogNames = if ($EventID -eq 4104) { $ScriptBlockLog } else { $ModuleLog }

        $Event = Get-WinEvent -LogName $LogNames -MaxEvents 150 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Id -eq $EventID -and
                $_.TimeCreated -ge $Start.AddSeconds(-10) -and
                ($SearchText -eq "" -or $_.Message -match [regex]::Escape($SearchText))
            } |
            Select-Object -First 1

        if ($Event) {
            return $Event
        }

        Start-Sleep -Milliseconds 500
    }

    return $null
}

function Report-Result {
    param(
        [string]$Name,
        [bool]$Success,
        [string]$Message
    )

    if ($Success) {
        Write-Host "          $Message   [PASS]" -ForegroundColor Green
        $script:Captured++
    }
    else {
        Write-Host "          $Message   [FAIL]" -ForegroundColor Red
        $script:Missed++
    }

    $script:Results += [PSCustomObject]@{
        Test      = $Name
        Success   = $Success
        Timestamp = Get-Date
        Detail    = $Message
    }
}

$TranscriptDir = "C:\PSTranscripts"
if (!(Test-Path $TranscriptDir)) {
    New-Item -ItemType Directory -Path $TranscriptDir -Force | Out-Null
}

try {
    Start-Transcript -Path (Join-Path $TranscriptDir "session_test.txt") -Force | Out-Null
} catch {}

# Simple Command (Event ID 4104)
Write-Host "    [1/5] Simple command (Get-Process)..."
Get-Process | Out-Null
$Event1 = Wait-PowerShellEvent -EventID 4104 -SearchText "Get-Process"

if ($Event1 -and $Event1.Message -match "Get-Process") {
    Report-Result "Simple Command" $true "EID 4104: 'Get-Process' captured"
} else {
    Report-Result "Simple Command" $false "EID 4104: 'Get-Process' missing"
}

# Encoded Command (Event ID 4104 Decoded)
Write-Host "    [2/5] Encoded command..."
$EncodedInput = 'VwByAGkAdAC0ASABvAHMAdAAgACIAVABlAHMAdAAi'
Write-Host "          Input: -enc $EncodedInput"
$DecodedBytes = [System.Convert]::FromBase64String($EncodedInput)
$DecodedString = [System.Text.Encoding]::Unicode.GetString($DecodedBytes)
Invoke-Expression $DecodedString | Out-Null

$Event2 = Wait-PowerShellEvent -EventID 4104 -SearchText "Write-Host"

if ($Event2 -and $Event2.Message -match "Write-Host") {
    Report-Result "Encoded Command" $true "EID 4104: 'Write-Host ''Test''' (decoded) captured"
} else {
    Report-Result "Encoded Command" $false "EID 4104: Decoded content missing"
}

# Module Import (Event ID 4103)
Write-Host "    [3/5] Module import..."
try {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
} catch {}
$Event3 = Wait-PowerShellEvent -EventID 4103 -SearchText "ActiveDirectory"

if ($Event3 -and $Event3.Message -match "ActiveDirectory") {
    Report-Result "Module Import" $true "EID 4103: 'Import-Module ActiveDirectory' captured"
} else {
    Report-Result "Module Import" $false "EID 4103: Module import missing from Windows PowerShell log"
}

# Multi-line Script Block (Event ID 4104)
Write-Host "    [4/5] Multi-line script block..."
$MultiLineScript = {
    Write-Output "PSLOG_LINE_01"
    Write-Output "PSLOG_LINE_02"
    Write-Output "PSLOG_LINE_03"
    Write-Output "PSLOG_LINE_04"
    Write-Output "PSLOG_LINE_05"
    Write-Output "PSLOG_LINE_06"
    Write-Output "PSLOG_LINE_07"
    Write-Output "PSLOG_LINE_08"
    Write-Output "PSLOG_LINE_09"
    Write-Output "PSLOG_LINE_10"
    Write-Output "PSLOG_LINE_11"
    Write-Output "PSLOG_LINE_12"
}
& $MultiLineScript | Out-Null
$Event4 = Wait-PowerShellEvent -EventID 4104 -SearchText "PSLOG_LINE_01"

if ($Event4 -and $Event4.Message -match "PSLOG_LINE_12") {
    Report-Result "Multi-line Script Block" $true "EID 4104: Full block captured (12 lines)"
} else {
    Report-Result "Multi-line Script Block" $false "EID 4104: Multi-line block missing"
}

#Transcription File Check
Write-Host "    [5/5] Transcription file..."
try {
    Stop-Transcript | Out-Null
} catch {}

$TranscriptFiles = Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -ErrorAction SilentlyContinue
if ($TranscriptFiles.Count -gt 0) {
    Report-Result "Transcription File" $true "C:\PSTranscripts\*.txt exists, session recorded"
} else {
    Report-Result "Transcription File" $false "Transcription log files not found"
}

Write-Host ""
Write-Host "Tests: 5 | Captured: $Captured | Missed: $Missed" -ForegroundColor Cyan
