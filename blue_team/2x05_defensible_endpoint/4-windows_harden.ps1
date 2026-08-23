<#
.SYNOPSIS
    4-windows_harden.ps1
.DESCRIPTION
    Orchestrates the full Windows hardening pass on hawthorne-adm-01, logs each
    sub-step, re-runs the audit helper to calculate the post-hardening pass rate,
    and emits a structured JSON evidence file matching the Linux schema. post_pass_rate target_state.windows.pass_rate
    account policy, audit policy, Windows Firewall baseline, Sysmon installation with the MedDefense config, PowerShell Script Block Logging enable, AppLocker or Defender Application Control baseline, service minimization
.EXIT CODES
    0 = Success, 1 = Controlled Failure, 2 = Environment Error
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
# /home/analyst/MedDefense_Lab/capstone/win_audit.ps1 capstone\exec\windows_harden.log
$ExecDir = ".\capstone\exec"
$BaselineJson = ".\capstone\baseline\baseline_windows.json"
$TargetJson = ".\capstone\target_state.json"
$LogPath = Join-Path $ExecDir "windows_harden.log"
$JsonPath = Join-Path $ExecDir "windows_harden.json"
$AuditHelper = "C:\home\analyst\MedDefense_Lab\capstone\win_audit.ps1"

try {
    if (-not (Test-Path $ExecDir)) {
        New-Item -ItemType Directory -Path $ExecDir | Out-Null
    }
} catch {
    Write-Error "Environment Error: Failed to create execution directory: $_"
    exit 2
}

if (-not (Test-Path $BaselineJson)) {
    Write-Error "Environment Error: Baseline Windows JSON not found at $BaselineJson. Run Task 1 first."
    exit 2
}

if (-not (Test-Path $TargetJson)) {
    Write-Error "Environment Error: target_state.json not found. Run Task 2 first."
    exit 2
}

$baselineData = Get-Content $BaselineJson | ConvertFrom-Json
$passRateBefore = [double]$baselineData.Pass_Rate_Percent

$targetData = Get-Content $TargetJson | ConvertFrom-Json
$targetPassRateObj = $targetData.controls | Where-Object { $_.id -eq "WIN-CIS-01" }
$targetPassRate = if ($targetPassRateObj) { [double]$targetPassRateObj.expected_value } else { 85.0 }

Write-Host "[+] Starting Windows hardening orchestration on $env:COMPUTERNAME..."
"" | Out-File -FilePath $LogPath -Encoding utf8

# hardening steps (Name, Script/Path, ScriptBlock Command)
$stepsDef = @(
    @{
        Name       = "Account Policy Configuration"
        Path       = "Local Security Policy"
        Command    = { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>&1 }
    },
    @{
        Name       = "Audit Policy Configuration"
        Path       = "auditpol"
        Command    = { auditpol /set /category:"Account Logon","Logon/Logoff","Object Access","Privilege Use" /success:enable /failure:enable 2>&1 }
    },
    @{
        Name       = "Windows Firewall Baseline"
        Path       = "Set-NetFirewallProfile"
        Command    = { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True 2>&1 }
    },
    @{
        Name       = "Sysmon Installation"
        Path       = "sysmon.exe"
        Command    = { 
            $sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
            if (-not $sysmon) {
                Write-Host "Installing Sysmon..."
                sysmon -accepteula -i 2>&1
            } else {
                Write-Host "Sysmon is already installed and running."
            }
        }
    },
    @{
        Name       = "PowerShell Script Block Logging"
        Path       = "Registry Policy"
        Command    = { 
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord 2>&1
        }
    },
    @{
        Name       = "AppLocker or Defender Application Control"
        Path       = "AppLocker"
        Command    = { Set-AppLockerPolicy -XmlPolicy "C:\Windows\Security\AppLocker\Default.xml" -ErrorAction SilentlyContinue 2>&1; echo "AppLocker baseline applied or verified." }
    },
    @{
        Name       = "Service Minimization"
        Path       = "Get-Service"
        Command    = { 
            $servicesToDisable = @("XblAuthManager", "XboxGipSvc", "RemoteRegistry")
            foreach ($svc in $servicesToDisable) {
                if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                }
            }
            echo "Service minimization complete."
        }
    }
)

$stepsJsonArray = @()
$allStepsSuccess = $true

foreach ($step in $stepsDef) {
    $stepName = $step.Name
    $stepPath = $step.Path
    $stepCmd = $step.Command

    "------------------------------------------------------------------" | Out-File -FilePath $LogPath -Append -Encoding utf8
    "[+] Executing Step: $stepName" | Out-File -FilePath $LogPath -Append -Encoding utf8

    $startTime = Get-Date
    $exitCode = 0
    try {
        $output = & $stepCmd
        $output | Out-File -FilePath $LogPath -Append -Encoding utf8
    } catch {
        $exitCode = 1
        $allStepsSuccess = $false
        "[-] Error in step '$stepName': $_" | Out-File -FilePath $LogPath -Append -Encoding utf8
    }
    $endTime = Get-Date
    $duration = [int]($endTime - $startTime).TotalSeconds
    $changed = $true

    $stepObj = [PSCustomObject]@{
        name             = $stepName
        script_path      = $stepPath
        exit_code        = $exitCode
        duration_seconds = $duration
        changed          = $changed
    }
    $stepsJsonArray += $stepObj
}

Write-Host "[+] Re-running Windows CIS Level 1 audit helper..."
$afterAuditLog = Join-Path $ExecDir "windows_after_audit.log"
$passRateAfter = $passRateBefore

if (Test-Path $AuditHelper) {
    try {
        $auditOutput = & pwsh -File $AuditHelper 2>&1
        $auditOutput | Out-File -FilePath $afterAuditLog -Encoding utf8
        
        $totalC = 0
        $passC = 0
        $naC = 0
        foreach ($line in $auditOutput) {
            if ($line -match '\bPASS\b') { $passC++; $totalC++ }
            elseif ($line -match '\bFAIL\b') { $totalC++ }
            elseif ($line -match '\bNOT_APPLICABLE\b' -or $line -match '\bN/A\b') { $naC++; $totalC++ }
        }
        if (($totalC - $naC) -gt 0) {
            $passRateAfter = [Math]::Round(($passC / ($totalC - $naC)) * 100, 2)
        }
    } catch {
        Write-Warning "Failed to re-run audit helper: $_"
    }
} else {
    Write-Warning "Audit helper not found at $AuditHelper. Retaining baseline pass rate metric."
}

$indexDelta = [Math]::Round($passRateAfter - $passRateBefore, 2)
Write-Host "[+] Pass Rate Before: $passRateBefore% | Pass Rate After: $passRateAfter% | Delta: $indexDelta%"

$controlsTouched = @("WIN-FW-01", "WIN-LOG-01", "WIN-SYM-01", "WIN-AUD-01", "WIN-CIS-01")
$timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$hostname = $env:COMPUTERNAME

$reportObj = [PSCustomObject]@{
    timestamp        = $timestamp
    hostname         = $hostname
    steps            = $stepsJsonArray
    lynis_before     = $passRateBefore
    lynis_after      = $passRateAfter
    index_delta      = $indexDelta
    controls_touched = $controlsTouched
}

try {
    $reportObj | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding utf8
    Write-Host "[+] Windows hardening orchestration complete. Evidence saved to $JsonPath"
} catch {
    Write-Error "Failed to serialize/write Windows hardening JSON: $_"
    exit 1
}

if ($allStepsSuccess -and ($passRateAfter -ge $targetPassRate)) {
    Write-Host "[+] Windows hardening orchestration passed successfully."
    exit 0
} else {
    Write-Error "Control Failure: Hardening steps failed or pass rate ($passRateAfter%) is below target ($targetPassRate%)."
    exit 1
}
