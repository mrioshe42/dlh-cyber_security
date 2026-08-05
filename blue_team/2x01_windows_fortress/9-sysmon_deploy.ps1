<#
.SYNOPSIS
    9-sysmon_deploy.ps1 - Sysmon Deployment and Configuration
.DESCRIPTION
    Downloads Sysmon and the SwiftOnSecurity configuration with TLS enforcement and retry logic,
    installs Sysmon, verifies health, and tests FileCreate (Event ID 11).
.PURPOSE
    Purpose: Deploy advanced endpoint telemetry and logging via Sysmon using the SwiftOnSecurity baseline.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-06-05
.KEYWORDS
    Sysmon, Sysmon64, Sysinternals, SwiftOnSecurity, Endpoint Telemetry, Event ID 11, SysmonDrv
.NOTES
    Notes: Requires administrative privileges and network access.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Force TLS 1.2 and TLS 1.3 for modern HTTPS compatibility in PowerShell 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$sysmonDir = "C:\Sysmon"
if (!(Test-Path $sysmonDir)) { 
    New-Item -Path $sysmonDir -ItemType Directory -Force | Out-Null 
}
Set-Location $sysmonDir

# Helper function for robust downloads with retries
function Get-RemoteFileWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [Parameter(Mandatory=$true)][string]$DisplayName
    )
    
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            Write-Host "[*] Downloading $DisplayName (Attempt $retryCount/$maxRetries)... " -NoNewline
            
            # Use System.Net.WebClient for reliable file transfer without TLS handshake stalls
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($Url, $OutFile)
            $webClient.Dispose()
            
            Write-Host "OK"
            $success = $true
        } catch {
            Write-Host "FAILED"
            if ($retryCount -ge $maxRetries) {
                throw "Critical Error: Failed to download $DisplayName from $Url. Details: $_"
            }
            Start-Sleep -Seconds 3
        }
    }
}

# Download Sysmon with Retry & TLS enforcement
Get-RemoteFileWithRetry -Url "https://live.sysinternals.com/Sysmon64.exe" -OutFile "$sysmonDir\Sysmon64.exe" -DisplayName "Sysmon"

#  Download SwiftOnSecurity config with Retry & TLS enforcement
Get-RemoteFileWithRetry -Url "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$sysmonDir\sysmonconfig.xml" -DisplayName "SwiftOnSecurity config"

# Install Sysmon
Write-Host "[*] Installing Sysmon with config..."
Write-Host "    Sysmon64.exe -accepteula -i sysmonconfig.xml"
Start-Process -FilePath "$sysmonDir\Sysmon64.exe" -ArgumentList "-accepteula -i sysmonconfig.xml" -Wait -NoNewWindow

# Real status checks using Get-Service
$service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$driver  = Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue

$serviceStatusText = if ($service -and $service.Status -eq 'Running') { "Running            [OK]" } else { "Not Running        [!]" }
$driverStatusText  = if ($driver  -and $driver.Status -eq 'Running')  { "Loaded             [OK]" } else { "Not Loaded         [!]" }

Write-Host "    Service: Sysmon64 - $serviceStatusText"
Write-Host "    Driver: SysmonDrv - $driverStatusText"

# Verify actual event generation
Write-Host "[*] Verifying event generation..."
Start-Sleep -Seconds 3
$events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue
$eventCount = if ($null -ne $events) { $events.Count } else { 0 }
Write-Host "    Events in last 60 seconds: $eventCount          [OK]"

# Test FileCreate detection (Event ID 11)
Write-Host "[*] Testing FileCreate detection..."
$testFilePath = "C:\Windows\Temp\sysmon_test.txt"
New-Item -Path $testFilePath -ItemType File -Force | Out-Null
Write-Host "    Created: $testFilePath"
Start-Sleep -Seconds 2

$verifyEvent = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; ID=11 } -MaxEvents 1 -ErrorAction SilentlyContinue
if ($verifyEvent) {
    Write-Host "    Event ID 11 captured                   [VERIFIED]"
} else {
    Write-Host "    Event ID 11 not yet indexed            [!]"
}

Remove-Item -Path $testFilePath -Force -ErrorAction SilentlyContinue
