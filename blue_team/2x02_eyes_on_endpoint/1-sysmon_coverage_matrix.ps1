 <#
.SYNOPSIS
    name : 1-sysmon_coverage_matrix.ps1
.PURPOSE
    purpose : Parse Sysmon XML configurations and map enabled event IDs and filtering rules against MITRE ATT&CK techniques to produce a coverage assessment matrix.
    author: Massimo Rios
.NOTES
    project : Endpoint Telemetry & Detection Engineering Suite
#>

Set-StrictMode -Version Latest

$XmlSource = Join-Path $PSScriptRoot "sysmonconfig.xml"
$JsonTarget = Join-Path $PSScriptRoot "sysmon_coverage_matrix.json"

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"

if (-not (Test-Path $XmlSource)) {
    Write-Host "[ERROR] sysmonconfig.xml not found."
    Exit 1
}

[xml]$Manifest = Get-Content $XmlSource

if ($null -eq $Manifest.Sysmon.EventFiltering) {
    Write-Host "[ERROR] EventFiltering section not found."
    Exit 1
}

# Lookup dictionary for telemetry tokens
$TelemetryDictionary = [ordered]@{
    "ProcessCreate"        = 1
    "FileCreateTime"       = 2
    "NetworkConnect"       = 3
    "ImageLoad"            = 7
    "CreateRemoteThread"   = 8
    "ProcessAccess"        = 10
    "FileCreate"           = 11
    "RegistryEvent"        = @(12, 13, 14)
    "FileCreateStreamHash" = 15
    "DNSQuery"             = 22
}

$ActiveTelemetryIds = [System.Collections.Generic.List[int]]::new()

foreach ($Tag in $TelemetryDictionary.Keys) {
    if (($Manifest.SelectNodes("//$Tag")).Count -gt 0) {
        foreach ($MappedCode in $TelemetryDictionary[$Tag]) {
            if (-not $ActiveTelemetryIds.Contains($MappedCode)) {
                $ActiveTelemetryIds.Add($MappedCode)
            }
        }
    }
}

# ATT&CK Mapping Blueprint
$ThreatCatalog = @(
    @{
        TID  = "T1059"
        Desc = "Command and Scripting Interpreter"
        Need = @(1)
        Tags = @("ProcessCreate")
        Data = @("Image", "CommandLine", "User", "ParentImage")
    },
    @{
        TID  = "T1053"
        Desc = "Scheduled Task/Job"
        Need = @(1)
        Tags = @("ProcessCreate")
        Data = @("Image", "CommandLine", "ParentImage")
    },
    @{
        TID  = "T1547"
        Desc = "Boot or Logon Autostart Execution"
        Need = @(13)
        Tags = @("RegistryEvent")
        Data = @("TargetObject", "Details", "Image")
    },
    @{
        TID  = "T1055"
        Desc = "Process Injection"
        Need = @(8, 10)
        Tags = @("CreateRemoteThread", "ProcessAccess")
        Data = @("SourceImage", "TargetImage", "GrantedAccess")
    },
    @{
        TID  = "T1071"
        Desc = "Application Layer Protocol"
        Need = @(3, 22)
        Tags = @("NetworkConnect", "DNSQuery")
        Data = @("Image", "DestinationIp", "DestinationPort", "QueryName")
    },
    @{
        TID  = "T1574.002"
        Desc = "DLL Side-Loading"
        Need = @(7)
        Tags = @("ImageLoad")
        Data = @("Image", "ImageLoaded", "Hashes")
    },
    @{
        TID  = "T1027"
        Desc = "Obfuscated or Compressed Files"
        Need = @(11, 15)
        Tags = @("FileCreate", "FileCreateStreamHash")
        Data = @("Image", "TargetFilename", "Hashes")
    }
)

$MatrixResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Item in $ThreatCatalog) {
    $ValidIds = @(foreach ($ReqId in $Item.Need) {
    if ($ActiveTelemetryIds.Contains($ReqId)) { $ReqId }
})

    $RuleConflicts = [System.Collections.Generic.List[string]]::new()
    foreach ($Sign in $Item.Tags) {
        foreach ($NodeElement in $Manifest.SelectNodes("//$Sign")) {
            if ($null -ne $NodeElement.onmatch -and $NodeElement.ChildNodes.Count -gt 0) {
                $RuleConflicts.Add("$Sign has $($NodeElement.onmatch) filtering")
            }
        }
    }

    if ($null -eq $ValidIds -or $ValidIds.Count -eq 0) {
        $State = "blind"
        $Tip = "Enable required Sysmon Event IDs."
    }
    elseif ($ValidIds.Count -lt $Item.Need.Count) {
        $State = "partial"
        $Tip = "Enable the missing Event IDs."
    }
    elseif ($RuleConflicts.Count -gt 0) {
        $State = "partial"
        $Tip = "Review include/exclude filters."
    }
    else {
        $State = "covered"
        $Tip = "No tuning required."
    }

    $MatrixResults.Add([PSCustomObject]@{
        technique_id             = $Item.TID
        technique_name           = $Item.Desc
        required_event_ids       = $Item.Need
        enabled_event_ids        = @($ValidIds)
        filter_conflicts         = @($RuleConflicts)
        coverage_status          = $State
        evidence_fields_expected = $Item.Data
        recommendation           = $Tip
    })
}

$MatrixResults | ConvertTo-Json -Depth 5 | Set-Content $JsonTarget

$CountCovered = @($MatrixResults | Where-Object { $_.coverage_status -eq "covered" }).Count
$CountPartial = @($MatrixResults | Where-Object { $_.coverage_status -eq "partial" }).Count
$CountBlind   = @($MatrixResults | Where-Object { $_.coverage_status -eq "blind" }).Count

Write-Host "Enabled Event IDs: $(($ActiveTelemetryIds | Sort-Object) -join ', ')"
Write-Host "Techniques assessed: $($MatrixResults.Count)"
Write-Host "Covered: $CountCovered"
Write-Host "Partial: $CountPartial"
Write-Host "Blind: $CountBlind"
Write-Host "Report saved to: sysmon_coverage_matrix.json" 
