<#
.SYNOPSIS
    1-baseline_snapshot.ps1
.DESCRIPTION
    Runs the Windows CIS Level 1 audit helper, parses pass/fail metrics,
    and exports structured baseline compliance data on hawthorne-adm-01.
.EXIT CODES
    0 = Success, 1 = Controlled Failure, 2 = Environment Error pass_rate_percent
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

$BaselineDir = ".\capstone\baseline"
$LogPath = Join-Path $BaselineDir "windows_baseline.log"
$JsonPath = Join-Path $BaselineDir "baseline_windows.json"
$AuditHelper = "C:\home\analyst\MedDefense_Lab\capstone\win_audit.ps1"

try {
    if (-not (Test-Path $BaselineDir)) {
        New-Item -ItemType Directory -Path $BaselineDir | Out-Null
    }
} catch {
    Write-Error "Failed to create baseline directory: $_"
    exit 2
}

if (-not (Test-Path $AuditHelper)) {
    Write-Error "Environment Error: Windows audit helper not found at $AuditHelper"
    exit 2
}

Write-Host "[+] Running Windows CIS Level 1 baseline audit on $env:COMPUTERNAME..."

try {
    $auditOutput = & pwsh -File $AuditHelper 2>&1
    $auditOutput | Out-File -FilePath $LogPath -Encoding utf8
} catch {
    Write-Error "Controlled Failure during audit script execution: $_"
    exit 1
}

$totalControls = 0
$passCount = 0
$failCount = 0
$naCount = 0

foreach ($line in $auditOutput) {
    if ($line -match '\bPASS\b') {
        $passCount++
        $totalControls++
    } elseif ($line -match '\bFAIL\b') {
        $failCount++
        $totalControls++
    } elseif ($line -match '\bNOT_APPLICABLE\b' -or $line -match '\bN/A\b') {
        $naCount++
        $totalControls++
    }
}

# Prevent division by zero controls_total
$passRatePercent = if ($totalControls -gt 0) {
    [Math]::Round(($passCount / ($totalControls - $naCount)) * 100, 2)
} else {
    0.0
}

$baselineData = [PSCustomObject]@{
    Timestamp          = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    Hostname           = $env:COMPUTERNAME
    Controls_Total     = $totalControls
    Pass_Count         = $passCount
    Fail_Count         = $failCount
    NA_Count           = $naCount
    Pass_Rate_Percent  = $passRatePercent
    Log_Path           = $LogPath
}

try {
    $baselineData | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonPath -Encoding utf8
    Write-Host "[+] Windows baseline snapshot complete. Evidence saved to $JsonPath"
    exit 0
} catch {
    Write-Error "Failed to serialize/write Windows baseline JSON: $_"
    exit 1
}
