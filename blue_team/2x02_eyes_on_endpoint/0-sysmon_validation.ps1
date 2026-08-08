<#
.SYNOPSIS
    name : 0-sysmon_validation.ps1
.DESCRIPTION
    Validates Sysmon event capture by triggering controlled actions (process creation, 
    network connections, file creation, registry modifications, and DNS queries) and 
    verifying that the expected Event IDs are successfully logged.
.PURPOSE
    purpose : Automate the validation of Sysmon telemetry capture on Windows hosts to ensure zero silent blind spots.
.AUTHOR
    author: Massimo Rios
.NOTES
    project : Requires permissions to read the Microsoft-Windows-Sysmon/Operational event log. Incorporates robust event waiting and detailed reporting.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

$Results = @()
$Captured = 0
$Missed = 0

Write-Host "[*] Running Sysmon telemetry validation..." -ForegroundColor Cyan

function Wait-SysmonEvent {
    param(
        [int]$EventID,
        [string]$SearchText,
        [int]$Timeout = 15
    )

    $Start = Get-Date

    while ((Get-Date) -lt $Start.AddSeconds($Timeout)) {

        $Event = Get-WinEvent -LogName $SysmonLog -MaxEvents 150 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Id -eq $EventID -and
                $_.TimeCreated -ge $Start.AddSeconds(-10) -and
                ($SearchText -eq "" -or $_.Message -match [regex]::Escape($SearchText))
            } |
            Select-Object -First 1

        if ($Event) {
            $Event | Add-Member `
                -MemberType NoteProperty `
                -Name Timestamp `
                -Value $Event.TimeCreated `
                -Force

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

Write-Host "    [1/5] Process creation (Event ID 1)..."
Start-Process cmd.exe "/c whoami" -Wait -NoNewWindow
$Event = Wait-SysmonEvent -EventID 1 -SearchText "whoami"

if (
    $Event -and
    $Event.Message -match "CommandLine"
) {
    Report-Result "Process Creation" $true "cmd.exe /c whoami -> Sysmon EID 1 captured, CommandLine present"
}
else {
    Report-Result "Process Creation" $false "Sysmon Event ID 1 missing CommandLine details"
}

Write-Host "    [2/5] Network connection (Event ID 3)..."
try {
    $WebRequest = [System.Net.HttpWebRequest]::Create("http://127.0.0.1/")
    $WebRequest.Timeout = 3000
    $null = $WebRequest.GetResponse()
} catch {}
$Event = Wait-SysmonEvent -EventID 3 -SearchText "127.0.0.1"

if (
    $Event -and 
    $Event.Message -match "DestinationIp" -and 
    $Event.Message -match "DestinationPort"
) {
    Report-Result "Network Connection" $true "Outbound TCP -> Sysmon EID 3 captured, network details present"
}
else {
    Report-Result "Network Connection" $false "Sysmon Event ID 3 missing network details"
}

Write-Host "    [3/5] File creation (Event ID 11)..."
$TestFile = "C:\Users\Public\sysmon_validation.txt"
Set-Content -Path $TestFile -Value "Validation test data" -Force
$Event = Wait-SysmonEvent -EventID 11 -SearchText "sysmon_validation.txt"

if (
    $Event -and 
    $Event.Message -match "TargetFilename"
) {
    Report-Result "File Creation" $true "$TestFile -> Sysmon EID 11 captured, TargetFilename details present"
}
else {
    Report-Result "File Creation" $false "Sysmon Event ID 11 missing TargetFilename details"
}

Write-Host "    [4/5] Registry modification (Event ID 13)..."
$RegKey = "HKCU:\Software\SysmonTest"
if (!(Test-Path $RegKey)) {
    New-Item $RegKey -Force | Out-Null
}
New-ItemProperty `
    -Path $RegKey `
    -Name "SysmonTest" `
    -Value "TelemetryValidation" `
    -PropertyType String `
    -Force | Out-Null
$Event = Wait-SysmonEvent -EventID 13 -SearchText "SysmonTest"

if (
    $Event -and 
    $Event.Message -match "TargetObject"
) {
    Report-Result "Registry Modification" $true "HKCU\Software\SysmonTest -> Sysmon EID 13 captured, registry details present"
}
else {
    Report-Result "Registry Modification" $false "Sysmon Event ID 13 missing registry details"
}

Write-Host "    [5/5] DNS query (Event ID 22)..."
[System.Net.Dns]::GetHostAddresses("example.com") | Out-Null
$Event = Wait-SysmonEvent -EventID 22 -SearchText "example.com"

if (
    $Event -and 
    $Event.Message -match "QueryName"
) {
    Report-Result "DNS Query" $true "DNS query example.com -> Sysmon EID 22 captured, QueryName present"
}
else {
    Report-Result "DNS Query" $false "Sysmon Event ID 22 missing DNS details"
}

Write-Host "[*] Cleanup: removing test artifacts..."
if (Test-Path $TestFile) {
    Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
}
if (Test-Path $RegKey) {
    Remove-ItemProperty -Path $RegKey -Name "SysmonTest" -Force -ErrorAction SilentlyContinue
    Remove-Item $RegKey -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Actions tested: $($Captured + $Missed) | Captured: $Captured | Missed: $Missed" -ForegroundColor Cyan

$Results | Export-Csv `
    -Path ".\sysmon_validation_results.csv" `
    -NoTypeInformation

Write-Host "Results exported to sysmon_validation_results.csv"
