<#
.SYNOPSIS
    2-eventlog_assessment.ps1 - Windows Event Log & Audit Policy Assessment
.DESCRIPTION
    Assesses current event logging capability by evaluating audit policy subcategories 
    via auditpol and querying the Security event log for activity within the last 24 hours.
.PURPOSE
    Purpose: Assess the current event logging capability and identify audit visibility gaps.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    2026-08-05
.NOTES
    Notes: Requires administrative execution for auditpol and Security log query privileges.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# Check current audit policy configuration using auditpol /get /category:*
$auditPolOutput = & auditpol.exe /get /category:* 2>&1

# Define critical Event IDs and their required audit subcategories
$criticalEvents = @(
    @{ Id = 4624; Description = "Successful Logon"; Subcategory = "Logon"; Log = "Security" },
    @{ Id = 4625; Description = "Failed Logon"; Subcategory = "Logon"; Log = "Security" },
    @{ Id = 4648; Description = "Explicit Credentials"; Subcategory = "Logon"; Log = "Security" },
    @{ Id = 4688; Description = "Process Creation"; Subcategory = "Process Tracking"; Log = "Security" },
    @{ Id = 4720; Description = "Account Created"; Subcategory = "Account Management"; Log = "Security" },
    @{ Id = 4726; Description = "Account Deleted"; Subcategory = "Account Management"; Log = "Security" },
    @{ Id = 4732; Description = "Member Added to Group"; Subcategory = "Account Management"; Log = "Security" },
    @{ Id = 4672; Description = "Special Logon"; Subcategory = "Special Logon"; Log = "Security" },
    @{ Id = 1102; Description = "Audit Log Cleared"; Subcategory = "System Integrity"; Log = "Security" }
)

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$timeThreshold = (Get-Date).AddDays(-1)

foreach ($eventDef in $criticalEvents) {
    $subcat = $eventDef.Subcategory
    $eventId = $eventDef.Id
    $logName = $eventDef.Log

    # Check if subcategory is enabled in auditpol output
    $isSubcatConfigured = $false
    if ($auditPolOutput) {
        $matchingLine = $auditPolOutput | Where-Object { $_ -match $subcat }
        if ($matchingLine -match "Success" -or $matchingLine -match "Failure") {
            $isSubcatConfigured = $true
        }
    }

    # Query Security log to confirm which Event IDs have actually been generated in the last 24 hours
    $eventGenerated = $false
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eventId; StartTime = $timeThreshold } -ErrorAction SilentlyContinue
        if ($events -and @($events).Count -gt 0) {
            $eventGenerated = $true
        }
    } catch {
        $eventGenerated = $false
    }

    # Determine status label
    $statusLabel = if ($eventGenerated) { "[GENERATING]" } else { "[NOT CONFIGURED]" }

    $results.Add([PSCustomObject]@{
        "Event ID"          = $eventId
        "Description"       = $eventDef.Description
        "Audit Subcategory" = $subcat
        "Status"            = $statusLabel
    })
}

$results | Format-Table -Property "Event ID", "Description", "Audit Subcategory", "Status" -AutoSize
