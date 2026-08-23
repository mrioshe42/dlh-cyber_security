<#
.SYNOPSIS
    5-telemetry_deploy.ps1
.DESCRIPTION
    Verifies Sysmon and Script Block Logging on hawthorne-adm-01, executes
    controlled test sequences, verifies event generation, and exports telemetry. Sysmon Operational, PowerShell Operational, Security
.EXIT CODES
    0 = Success, 1 = Controlled Failure, 2 = Environment Error
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
#capstone\telemetry\windows_coverage.json capstone\telemetry\windows_events.json
$TelemetryDir = ".\capstone\telemetry"
$JsonPath = Join-Path $TelemetryDir "windows_events.json"
$CoverageJson = Join-Path $TelemetryDir "windows_coverage.json"

try {
    if (-not (Test-Path $TelemetryDir)) {
        New-Item -ItemType Directory -Path $TelemetryDir | Out-Null
    }
} catch {
    Write-Error "Failed to create telemetry directory: $_"
    exit 2
}

Write-Host "[+] Verifying Windows telemetry stack..."

$sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if (-not $sysmon -or $sysmon.Status -ne 'Running') {
    Write-Error "Environment Error: Sysmon is not installed or not running."
    exit 2
}

$sblPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sblEnabled = 0
if (Test-Path $sblPath) {
    $sblEnabled = (Get-ItemProperty -Path $sblPath).EnableScriptBlockLogging
}
if ($sblEnabled -ne 1) {
    Write-Error "Environment Error: Script Block Logging is not enabled in policies."
    exit 2
}

Write-Host "[+] Executing controlled test sequence..."
$testResults = @()
$allPassed = $true

# Local User Creation Trace
$testName = "Local User Creation"
$verified = $true
try {
    New-LocalUser -Name "TestCapstoneUser" -Password (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -ErrorAction SilentlyContinue
    Remove-LocalUser -Name "TestCapstoneUser" -ErrorAction SilentlyContinue
    $event = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720; StartTime=(Get-Date).AddMinutes(-5) } -MaxEvents 1 -ErrorAction SilentlyContinue
    if (-not $event) { $verified = $false }
} catch {
    $verified = $false
}
if (-not $verified) { $allPassed = $false }
$testResults += [PSCustomObject]@{ test_name = $testName; channel = "Security"; verified = $verified }

# PowerShell Script Block Logging Trace
$testName = "PowerShell Script Block Logging"
$verified = $true
try {
    Invoke-Command -ScriptBlock { $dummyVar = "MedDefenseTestExecution" }
    $event = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-5) } -MaxEvents 1 -ErrorAction SilentlyContinue
    if (-not $event) { $verified = $false }
} catch {
    $verified = $false
}
if (-not $verified) { $allPassed = $false }
$testResults += [PSCustomObject]@{ test_name = $testName; channel = "PowerShell Operational"; verified = $verified }

$recentSysmon = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-30) } -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message

$exportData = [PSCustomObject]@{
    timestamp           = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    hostname            = $env:COMPUTERNAME
    sysmon_event_count  = @($recentSysmon).Count
    sbl_enabled         = $sblEnabled
}

$exportData | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonPath -Encoding utf8

$coverageData = [PSCustomObject]@{
    timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    hostname       = $env:COMPUTERNAME
    coverage_tests = $testResults
}

$coverageData | ConvertTo-Json -Depth 3 | Out-File -FilePath $CoverageJson -Encoding utf8

if ($allPassed) {
    Write-Host "[+] Windows telemetry deployment and coverage verification passed successfully."
    exit 0
} else {
    Write-Error "Control Failure: One or more Windows telemetry verification checks failed."
    exit 1
}
