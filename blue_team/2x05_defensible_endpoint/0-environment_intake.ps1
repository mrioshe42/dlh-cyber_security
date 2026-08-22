<#
.SYNOPSIS
    0-environment_intake.ps1
.DESCRIPTION
    Captures the unhardened raw baseline state of hawthorne-adm-01
    into a structured JSON artifact for delta comparison.
.EXIT CODES
    0 = Success, 1 = Controlled Failure, 2 = Environment Error
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$OutputDir = ".\evidence"
$OutputFile = Join-Path $OutputDir "windows_intake_baseline.json"

try {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
} catch {
    Write-Error "Failed to create output directory: $_"
    exit 2
}

Write-Host "[+] Starting Windows environment intake on $env:COMPUTERNAME..."

$osInfo = Get-CimInstance Win32_OperatingSystem
$hostname = $env:COMPUTERNAME
$osBuild = $osInfo.BuildNumber
$osVersion = $osInfo.Version

try {
    $features = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | Select-Object -ExpandProperty FeatureName
} catch {
    $features = @("Unavailable on current SKU")
}

$services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName
$localUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired
$firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if (Test-Path $psLoggingPath) {
    $scriptBlockLogging = (Get-ItemProperty -Path $psLoggingPath).EnableScriptBlockLogging
} else {
    $scriptBlockLogging = 0
}

# Account Lockout & Password Policy via net accounts
$netAccountsRaw = net accounts 2>&1
$netAccountsObj = @{}
foreach ($line in $netAccountsRaw) {
    if ($line -match '^(.*?)\s{2,}(.*)$') {
        $netAccountsObj[$matches[1].Trim()] = $matches[2].Trim()
    }
}

# Sysmon check
$sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
$sysmonStatus = if ($sysmonService) { $sysmonService.Status } else { "NotInstalled" }

$baselineData = [PSCustomObject]@{
    Timestamp              = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    Hostname               = $hostname
    OS_Build               = $osBuild
    OS_Version             = $osVersion
    Enabled_Features_Count = @($features).Count
    Running_Services_Count = @($services).Count
    Local_Users            = $localUsers
    Firewall_Profiles      = $firewallProfiles
    Script_Block_Logging   = $scriptBlockLogging
    Net_Accounts_Policy    = $netAccountsObj
    Sysmon_Status          = $sysmonStatus
}

try {
    $baselineData | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Windows intake complete. Evidence saved to $OutputFile"
    exit 0
} catch {
    Write-Error "Failed to serialize/write output JSON: $_"
    exit 1
}
