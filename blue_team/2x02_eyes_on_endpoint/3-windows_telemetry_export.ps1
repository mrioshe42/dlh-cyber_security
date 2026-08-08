<#
.SYNOPSIS
    name : 3-windows_telemetry_export.ps1
.PURPOSE
    purpose : Export, normalize, and enrich Windows Security, Sysmon, and PowerShell telemetry into an analyst-ready JSON package.
    author: Massimo Rios
.NOTES
    project : Endpoint Telemetry & Detection Engineering Suite, ScriptBlockText
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$OutputJsonPath = Join-Path $PSScriptRoot "windows_events_export.json"
$TimeWindowHours = 24
$StartTime = (Get-Date).AddHours(-$TimeWindowHours)

Write-Host "[*] Exporting Windows telemetry from last $TimeWindowHours hours..." -ForegroundColor Cyan

$Channels = @(
    @{ Name = "Security"; Type = "Security" },
    @{ Name = "Microsoft-Windows-Sysmon/Operational"; Type = "Sysmon" },
    @{ Name = "Microsoft-Windows-PowerShell/Operational"; Type = "PowerShell" }
)

$AllExportedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$ChannelCounts = [ordered]@{}

foreach ($ChannelConfig in $Channels) {
    $ChannelName = $ChannelConfig.Name
    $SourceType = $ChannelConfig.Type
    
    $RawEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $ChannelName
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
    # EndTime
    $Count = 0
    if ($RawEvents) {
        foreach ($Event in $RawEvents) {
            $Count++
            $XmlDoc = [xml]$Event.ToXml()
            $EventData = @{}
            
            if ($XmlDoc.Event.EventData.Data) {
                foreach ($DataNode in $XmlDoc.Event.EventData.Data) {
                    $Key = $DataNode.Name
                    if (-not $Key) {
                        $Key = "Param_$($EventData.Count)"
                    }
                    if (-not $EventData.ContainsKey($Key)) {
                        $EventData[$Key] = $DataNode.InnerText
                    }
                }
            }

            $EventId = [int]$Event.Id
            $Category = "General"
            $Enriched = [ordered]@{}

            # Normalization & Enrichment routing per Event ID
            switch ($EventId) {
                4624 {
                    $Category = "Logon"
                    $Enriched.target_user   = $EventData["TargetUserName"]
                    $Enriched.logon_type    = $EventData["LogonType"]
                    $Enriched.source_ip     = $EventData["IpAddress"]
                    $Enriched.workstation   = $EventData["WorkstationName"]
                }
                4625 {
                    $Category = "LogonFailure"
                    $Enriched.target_user   = $EventData["TargetUserName"]
                    $Enriched.failure_reason= $EventData["Status"]
                    $Enriched.source_ip     = $EventData["IpAddress"]
                }
                4672 {
                    $Category = "Privilege"
                    $Enriched.privileged_account = $EventData["SubjectUserName"]
                }
                4688 {
                    $Category = "ProcessCreation"
                    $Enriched.process_name  = $EventData["NewProcessName"]
                    $Enriched.command_line  = $EventData["CommandLine"]
                    $Enriched.parent_process= $EventData["ParentProcessName"]
                }
                4104 {
                    $Category = "ScriptBlock"
                    $Enriched.decoded_script= $Event.Message
                }
                1 {
                    if ($SourceType -eq "Sysmon") {
                        $Category = "ProcessCreate"
                        $Enriched.image          = $EventData["Image"]
                        $Enriched.command_line   = $EventData["CommandLine"]
                        $Enriched.parent_image   = $EventData["ParentImage"]
                        $Enriched.hashes         = $EventData["Hashes"]
                    }
                }
                3 {
                    if ($SourceType -eq "Sysmon") {
                        $Category = "NetworkConnect"
                        $Enriched.destination_ip   = $EventData["DestinationIp"]
                        $Enriched.destination_port = $EventData["DestinationPort"]
                        $Enriched.process          = $EventData["Image"]
                    }
                }
                11 {
                    if ($SourceType -eq "Sysmon") {
                        $Category = "FileCreate"
                        $Enriched.target_filename   = $EventData["TargetFilename"]
                        $Enriched.creating_process  = $EventData["Image"]
                    }
                }
                13 {
                    if ($SourceType -eq "Sysmon") {
                        $Category = "Registry"
                        $Enriched.registry_key  = $EventData["TargetObject"]
                        $Enriched.value_name    = $EventData["Details"]
                    }
                }
                22 {
                    if ($SourceType -eq "Sysmon") {
                        $Category = "DNSQuery"
                        $Enriched.query_name    = $EventData["QueryName"]
                        $Enriched.query_results = $EventData["QueryResults"]
                    }
                }
            }

            $AllExportedRecords.Add([PSCustomObject]@{
                timestamp      = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                hostname       = $env:COMPUTERNAME
                platform       = "Windows"
                source_type    = $SourceType
                channel        = $ChannelName
                event_id       = $EventId
                event_category = $Category
                provider       = $Event.ProviderName
                raw_message    = $Event.Message
                enriched_fields= $Enriched
            })
        }
    }

    $ChannelCounts[$SourceType] = $Count
}

$AllExportedRecords | ConvertTo-Json -Depth 6 | Set-Content $OutputJsonPath

$SecurityTotal = $ChannelCounts["Security"]
$SysmonTotal   = $ChannelCounts["Sysmon"]
$PowerShellTotal = $ChannelCounts["PowerShell"]
$GrandTotal    = $SecurityTotal + $SysmonTotal + $PowerShellTotal

$TopIds = $AllExportedRecords | Group-Object event_id | Sort-Object Count -Descending | Select-Object -First 4

Write-Host "Security events: $SecurityTotal"
Write-Host "Sysmon events: $SysmonTotal"
Write-Host "PowerShell events: $PowerShellTotal"
Write-Host "Total events: $GrandTotal"
Write-Host "Top Event IDs: $(($TopIds | ForEach-Object { if ($_.Group[0].source_type -eq "Sysmon") { "Sysmon-$($_.Name)" } else { $_.Name } }) -join ', ')"
Write-Host "Output: windows_events_export.json"
