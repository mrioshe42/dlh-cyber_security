<#
.SYNOPSIS
    3-telemetry_reference.ps1 - Windows Telemetry Reference Builder
.DESCRIPTION
    Builds a machine-readable Windows event reference JSON file connecting security events 
    to MedDefense detection use cases and prints telemetry metrics.
.PURPOSE
    Purpose: Establish a formalized telemetry reference mapping critical Windows events to detection use cases for the MedDefense domain.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date : 2026-08-05
.NOTES
    Notes: Generates telemetry_reference.json containing event-to-use-case mappings and telemetry metrics.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$events = @(
    # Security Events (9)
    @{
        event_id                  = 4624
        event_name                = "Successful Logon"
        log_source                = "Security"
        audit_or_sensor_dependency = "Logon"
        security_meaning          = "User successfully authenticated to the system"
        normal_frequency          = "High"
        triage_priority           = "Low"
        crimson_tide_phase        = "Initial Access"
        example_suspicious_pattern = "Unusual logon type or off-hours service account login"
        validation_method         = "Interactive login or remote session"
    },
    @{
        event_id                  = 4625
        event_name                = "failed logon"
        log_source                = "Security"
        audit_or_sensor_dependency = "Logon"
        security_meaning          = "Logon attempt failed due to bad credentials or account restrictions"
        normal_frequency          = "Medium"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Credential Access"
        example_suspicious_pattern = "Brute-force attack pattern (many failures followed by success)"
        validation_method         = "Invalid password login attempt"
    },
    @{
        event_id                  = 4648
        event_name                = "Explicit Credentials"
        log_source                = "Security"
        audit_or_sensor_dependency = "Logon"
        security_meaning          = "Logon attempted using explicit credentials (RunAs)"
        normal_frequency          = "Low"
        triage_priority           = "High"
        crimson_tide_phase        = "Lateral Movement"
        example_suspicious_pattern = "RunAs execution using administrative credentials from standard session"
        validation_method         = "Start-Process -Credential"
    },
    @{
        event_id                  = 4672
        event_name                = "Special Logon"
        log_source                = "Security"
        audit_or_sensor_dependency = "Special Logon"
        security_meaning          = "Special privileges assigned to new logon (Admin login)"
        normal_frequency          = "Low"
        triage_priority           = "High"
        crimson_tide_phase        = "Privilege Escalation"
        example_suspicious_pattern = "SeDebugPrivilege assigned to non-system account"
        validation_method         = "Domain Admin interactive login"
    },
    @{
        event_id                  = 4688
        event_name                = "Process Creation"
        log_source                = "Security"
        audit_or_sensor_dependency = "Process Tracking"
        security_meaning          = "A new process has been created"
        normal_frequency          = "Very High"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Execution"
        example_suspicious_pattern = "cmd.exe spawned by powershell.exe executing encoded command"
        validation_method         = "Start-Process cmd.exe"
    },
    @{
        event_id                  = 4720
        event_name                = "Account Created"
        log_source                = "Security"
        audit_or_sensor_dependency = "Account Management"
        security_meaning          = "A user account was created"
        normal_frequency          = "Low"
        triage_priority           = "High"
        crimson_tide_phase        = "Persistence"
        example_suspicious_pattern = "Unexpected user account created outside authorized change window"
        validation_method         = "New-ADUser"
    },
    @{
        event_id                  = 4726
        event_name                = "Account Deleted"
        log_source                = "Security"
        audit_or_sensor_dependency = "Account Management"
        security_meaning          = "A user account was deleted"
        normal_frequency          = "Low"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Defense Evasion"
        example_suspicious_pattern = "Removal of legitimate administrator or forensic account"
        validation_method         = "Remove-ADUser"
    },
    @{
        event_id                  = 4732
        event_name                = "Member Added to Group"
        log_source                = "Security"
        audit_or_sensor_dependency = "Account Management"
        security_meaning          = "Member added to security-enabled local group"
        normal_frequency          = "Low"
        triage_priority           = "High"
        crimson_tide_phase        = "Privilege Escalation"
        example_suspicious_pattern = "Account added to Domain Admins or local Administrators"
        validation_method         = "Add-ADGroupMember"
    },
    @{
        event_id                  = 1102
        event_name                = "Audit Log Cleared"
        log_source                = "Security"
        audit_or_sensor_dependency = "System Integrity"
        security_meaning          = "The audit log was cleared"
        normal_frequency          = "Zero"
        triage_priority           = "Critical"
        crimson_tide_phase        = "Defense Evasion"
        example_suspicious_pattern = "Manual clearing of Security event log post-compromise"
        validation_method         = "Clear-EventLog Security"
    },

    # PowerShell Events (2)
    @{
        event_id                  = 4103
        event_name                = "Module Logging"
        log_source                = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Module Logging"
        security_meaning          = "Pipeline execution and module activity captured"
        normal_frequency          = "High"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Execution"
        example_suspicious_pattern = "Execution of suspicious loaded modules or obfuscated scripts"
        validation_method         = "Import-Module / Script execution"
    },
    @{
        event_id                  = 4104
        event_name                = "Script Block Logging"
        log_source                = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Script Block Logging"
        security_meaning          = "Full text of executed script blocks captured"
        normal_frequency          = "High"
        triage_priority           = "High"
        crimson_tide_phase        = "Execution"
        example_suspicious_pattern = "De-obfuscated script text containing credential theft or web downloads"
        validation_method         = "Invoke-Expression 'Get-Process'"
    },

    # Sysmon Events (6)
    @{
        event_id                  = 1
        event_name                = "Process Creation (Sysmon)"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 1"
        security_meaning          = "Detailed process execution including hashes and command line arguments"
        normal_frequency          = "Very High"
        triage_priority           = "High"
        crimson_tide_phase        = "Execution"
        example_suspicious_pattern = "PowerShell downloading payload via WebClient with hidden window"
        validation_method         = "Start-Process"
    },
    @{
        event_id                  = 3
        event_name                = "Network Connection"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 3"
        security_meaning          = "Network connection initiated or accepted by process"
        normal_frequency          = "High"
        triage_priority           = "High"
        crimson_tide_phase        = "Command and Control"
        example_suspicious_pattern = "Process connecting to external C2 IP on uncommon port"
        validation_method         = "Test-NetConnection"
    },
    @{
        event_id                  = 7
        event_name                = "Image Loaded (DLL)"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 7"
        security_meaning          = "DLL loaded into process address space"
        normal_frequency          = "Very High"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Defense Evasion"
        example_suspicious_pattern = "Unsigned DLL injection into trusted process (e.g. lsass.exe)"
        validation_method         = "DLL load simulation"
    },
    @{
        event_id                  = 11
        event_name                = "File Create"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 11"
        security_meaning          = "File created or overwritten"
        normal_frequency          = "High"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Impact"
        example_suspicious_pattern = "ransomware dropping note or encrypted files across endpoints"
        validation_method         = "New-Item"
    },
    @{
        event_id                  = 13
        event_name                = "Registry Event"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 13"
        security_meaning          = "Registry key or value set/modified"
        normal_frequency          = "High"
        triage_priority           = "High"
        crimson_tide_phase        = "Persistence"
        example_suspicious_pattern = "Run key modification or service creation in registry"
        validation_method         = "New-ItemProperty"
    },
    @{
        event_id                  = 22
        event_name                = "DNS Query"
        log_source                = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon Config Event 22"
        security_meaning          = "DNS query performed by process"
        normal_frequency          = "Very High"
        triage_priority           = "Medium"
        crimson_tide_phase        = "Command and Control"
        example_suspicious_pattern = "Querying dynamic DNS or DGA domains associated with malware"
        validation_method         = "Resolve-DnsName"
    }
)

$jsonPath = "windows_event_reference.json"
$events | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8

$secCount = ($events | Where-Object { $_.log_source -eq "Security" }).Count
$psCount = ($events | Where-Object { $_.log_source -like "*PowerShell*" }).Count
$sysCount = ($events | Where-Object { $_.log_source -like "*Sysmon*" }).Count
$totalCount = $events.Count

Write-Host "Security events mapped: $secCount"
Write-Host "PowerShell events mapped: $psCount"
Write-Host "Sysmon events mapped: $sysCount"
Write-Host "Total events documented: $totalCount"
Write-Host "Reference saved to: $jsonPath"
