<#
.SYNOPSIS
    name : 4-windows_telemetry_quality.ps1
.PURPOSE
    purpose : Assess exported Windows telemetry completeness, time continuity, and field quality to produce a weighted readiness report.
    author: Massimo Rios
.NOTES
    project : Endpoint Telemetry & Detection Engineering Suite
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InputJsonPath = Join-Path $PSScriptRoot "windows_events_export.json"
$OutputJsonPath = Join-Path $PSScriptRoot "windows_telemetry_quality.json"

$WindowHours = 24
$GapThresholdMinutes = 30

if (!(Test-Path $InputJsonPath)) {
    Write-Error "Input file 'windows_events_export.json' not found. Run telemetry export first."
    exit 1
}

Write-Host "[*] Analyzing windows_events_export.json..." -ForegroundColor Cyan

# Load exported events per hour
$Events = @(Get-Content $InputJsonPath -Raw | ConvertFrom-Json)
$TotalEvents = $Events.Count

if ($TotalEvents -eq 0) {
    Write-Error "No events found in the export file to analyze."
    exit 1
}

function Get-EventValue {
    param($Event, [string]$Name)
    if ($null -eq $Event) { 
        return $null
    }
    
    if ($Event.PSObject.Properties['enriched_fields'] -and $null -ne $Event.enriched_fields) {
        if ($Event.enriched_fields.PSObject.Properties[$Name]) {
            return $Event.enriched_fields.$Name
        }
    }
    
    $property = $Event.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Test-FieldValue {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        return $false
    }
    if ([string]$Value -eq "-" -or [string]$Value -eq "::1") {
        return $false
    }
    return $true
}

function Get-Percent {
    param([int]$Good, [int]$Total)
    if ($Total -eq 0) {
        return 100.0
    }
    return [math]::Round(($Good / $Total) * 100, 2)
}

# 1. Event Distribution
$EventDistribution = [ordered]@{}
$EventIdGroups = $Events | Group-Object event_id | Sort-Object Count -Descending
foreach ($Group in $EventIdGroups) {
    $Percentage = Get-Percent $Group.Count $TotalEvents
    $EventDistribution[$Group.Name] = @{
        count      = $Group.Count
        percentage = $Percentage
    }
}

# Channel Distribution
$ChannelDistribution = [ordered]@{}
$ChannelGroups = $Events | Group-Object source_type
foreach ($Group in $ChannelGroups) {
    $ChannelDistribution[$Group.Name] = $Group.Count
}

foreach ($Chan in @("Security", "Sysmon", "PowerShell")) {
    if (-not $ChannelDistribution.Contains($Chan)) {
        $ChannelDistribution[$Chan] = 0
    }
}

# Time Coverage & Gap Detection
$EndTime = (Get-Date).ToUniversalTime()
$StartTime = $EndTime.AddHours(-$WindowHours)

$TimedEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($Event in $Events) {
    try {
        $Time = [DateTimeOffset]::Parse($Event.timestamp).UtcDateTime
        if ($Time -ge $StartTime -and $Time -le $EndTime) {
            $TimedEvents.Add([PSCustomObject]@{
                time  = $Time
                event = $Event
            })
        }
    }
    catch {
        # Ignore invalid timestamp format records safely
    }
}

$EventsPerHour = @()
for ($i = 0; $i -lt $WindowHours; $i++) {
    $HourStart = $StartTime.AddHours($i)
    $HourEnd = $HourStart.AddHours(1)

    $Count = @(
        $TimedEvents | Where-Object { $_.time -ge $HourStart -and $_.time -lt $HourEnd }
    ).Count

    $EventsPerHour += [PSCustomObject]@{
        hour        = $HourStart.ToString("yyyy-MM-dd HH:00")
        event_count = $Count
    }
}

$HoursWithEventsList = @(
    $EventsPerHour | Where-Object { $_.event_count -gt 0 }
)
$HoursWithEventsCount = $HoursWithEventsList.Count
$HoursWithoutEventsCount = [Math]::Max(0, $WindowHours - $HoursWithEventsCount)

# Gap Detection
$Gaps = @()
$AllGapMinutes = @()
$SortedTimes = @($TimedEvents | Sort-Object time | Select-Object -ExpandProperty time)

if ($SortedTimes.Count -gt 0) {
    $FirstGap = ($SortedTimes[0] - $StartTime).TotalMinutes
    $AllGapMinutes += $FirstGap
    if ($FirstGap -gt $GapThresholdMinutes) {
        $Gaps += [PSCustomObject]@{
            start   = $StartTime.ToString("o")
            end     = $SortedTimes[0].ToString("o")
            minutes = [math]::Round($FirstGap, 2)
        }
    }

    for ($i = 1; $i -lt $SortedTimes.Count; $i++) {
        $Minutes = ($SortedTimes[$i] - $SortedTimes[$i - 1]).TotalMinutes
        $AllGapMinutes += $Minutes
        if ($Minutes -gt $GapThresholdMinutes) {
            $Gaps += [PSCustomObject]@{
                start   = $SortedTimes[$i - 1].ToString("o")
                end     = $SortedTimes[$i].ToString("o")
                minutes = [math]::Round($Minutes, 2)
            }
        }
    }

    $LastGap = ($EndTime - $SortedTimes[-1]).TotalMinutes
    $AllGapMinutes += $LastGap
    if ($LastGap -gt $GapThresholdMinutes) {
        $Gaps += [PSCustomObject]@{
            start   = $SortedTimes[-1].ToString("o")
            end     = $EndTime.ToString("o")
            minutes = [math]::Round($LastGap, 2)
        }
    }
} else {
    $AllGapMinutes += ($WindowHours * 60)
    $Gaps += [PSCustomObject]@{
        start   = $StartTime.ToString("o")
        end     = $EndTime.ToString("o")
        minutes = ($WindowHours * 60)
    }
}

$MaxGapMinutes = if ($AllGapMinutes.Count -gt 0) { ($AllGapMinutes | Measure-Object -Maximum).Maximum } else { 0 }

# Field Completeness
$ProcessEvents = @($Events | Where-Object { $_.event_id -eq 4688 -or ($_.source_type -eq "Sysmon" -and $_.event_id -eq 1) })
$CmdLineGood = 0
foreach ($Ev in $ProcessEvents) {
    if (Test-FieldValue (Get-EventValue $Ev "command_line")) { $CmdLineGood++ }
}
$CmdLineCompleteness = Get-Percent $CmdLineGood $ProcessEvents.Count

$LogonEvents = @($Events | Where-Object { $_.event_id -eq 4624 -or $_.event_id -eq 4625 })
$IpGood = 0
foreach ($Ev in $LogonEvents) {
    if (Test-FieldValue (Get-EventValue $Ev "source_ip")) { $IpGood++ }
}
$SourceIpCompleteness = Get-Percent $IpGood $LogonEvents.Count

$PsEvents = @($Events | Where-Object { $_.event_id -eq 4104 })
$ScriptGood = 0
foreach ($Ev in $PsEvents) {
    $Val = Get-EventValue $Ev "decoded_script"
    if (-not $Val) { $Val = Get-EventValue $Ev "ScriptBlockText" }
    if (Test-FieldValue $Val) { $ScriptGood++ }
}
$ScriptBlockCompleteness = Get-Percent $ScriptGood $PsEvents.Count

# Quality Score Calculation
$CompletenessAvg = ($CmdLineCompleteness + $SourceIpCompleteness + $ScriptBlockCompleteness) / 3
$ContinuityScore = ($HoursWithEventsCount / $WindowHours) * 100

$GapScore = if ($MaxGapMinutes -le 30) {
    100
} elseif ($MaxGapMinutes -le 60) {
    80
} elseif ($MaxGapMinutes -le 120) {
    60
} else {
    30
}

$ActiveChannelsCount = @($ChannelDistribution.GetEnumerator() | Where-Object { $_.Value -gt 0 }).Count
$ChannelScore = ($ActiveChannelsCount / 3) * 100

$QualityScore = [math]::Round(($CompletenessAvg * 0.40) + ($ContinuityScore * 0.30) + ($GapScore * 0.20) + ($ChannelScore * 0.10), 1)
if ($QualityScore -lt 0) { $QualityScore = 0.0 }
if ($QualityScore -gt 100) { $QualityScore = 100.0 }

$Assessment = if ($QualityScore -ge 85) {
    "good"
} elseif ($QualityScore -ge 65) {
    "acceptable"
} else {
    "poor"
}

$QualityReport = [PSCustomObject]@{
    metadata = [PSCustomObject]@{
        generated_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        total_events = $TotalEvents
    }
    summary = [PSCustomObject]@{
        quality_score           = $QualityScore
        assessment              = $Assessment
        hours_with_events_ratio = "$HoursWithEventsCount/$WindowHours"
        largest_gap_minutes     = [int]$MaxGapMinutes
    }
    time_coverage = [PSCustomObject]@{
        window_hours         = $WindowHours
        events_per_hour      = $EventsPerHour
        hours_with_events    = $HoursWithEventsCount
        hours_without_events = $HoursWithoutEventsCount
    }
    gap_detection = [PSCustomObject]@{
        threshold_minutes   = $GapThresholdMinutes
        largest_gap_minutes = [math]::Round($MaxGapMinutes, 2)
        gaps                = $Gaps
    }
    completeness = [PSCustomObject]@{
        command_line_completeness = "$CmdLineCompleteness%"
        source_ip_completeness    = "$SourceIpCompleteness%"
        script_block_completeness = "$ScriptBlockCompleteness%"
    }
    distributions = [PSCustomObject]@{
        channels  = $ChannelDistribution
        event_ids = $EventDistribution
    }
}

$QualityReport | ConvertTo-Json -Depth 10 | Set-Content $OutputJsonPath -Encoding UTF8

Write-Host "Total events: $TotalEvents"
Write-Host "Hours with events: $HoursWithEventsCount/$WindowHours"
Write-Host "Largest gap: $([int]$MaxGapMinutes) minutes"
Write-Host "Command-line completeness: $CmdLineCompleteness%"
Write-Host "Source IP completeness: $SourceIpCompleteness%"
Write-Host "Script block completeness: $ScriptBlockCompleteness%"
Write-Host "Quality score: $QualityScore% ($Assessment)"
Write-Host "Report saved to: windows_telemetry_quality.json"
