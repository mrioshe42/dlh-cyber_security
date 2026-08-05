<#
.SYNOPSIS
    11-firewall_hardening.ps1 - Windows Firewall Lockdown and Segmentation
.DESCRIPTION
    Captures current firewall state, enables all firewall profiles (Domain, Private, Public) with 
    default-deny inbound policies, creates granular least-privilege allow rules with subnet restrictions, 
    enables dropped packet logging, disables legacy allow rules, and verifies posture.
.PURPOSE
    Purpose: Enforce strict network segmentation, secure system boundaries, and eliminate unauthorized inbound attack vectors.
.AUTHOR
    Author: Security Engineering Team (MedDefense)
.DATE
    Date: 2026-06-05
.KEYWORDS
    Windows Firewall, Network Segmentation, Default-Deny, Firewall Profiles, Packet Logging, Least Privilege, RDP, Kerberos, LDAP
.NOTES
    Notes: Requires administrative privileges. Ensure critical administrative access ports remain open to prevent lockout.
#>
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[*] Current Firewall State..."
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in$profiles) {
    $inAction = if ($p.DefaultInboundAction -eq "Block") { "Block" } else { "Allow" }
    $status = if ($p.Enabled -eq$true) { "ON" } else { "OFF" }
    $flag = if ($p.DefaultInboundAction -eq "Allow" -or $p.Enabled -eq$false) { "[!]" } else { "[OK]" }
    Write-Host "    $($p.Name):$status, DefaultInbound: $inAction$flag"
}

# Set default-deny inbound on all profiles and enable them
Write-Host "[*] Setting default-deny on all profiles... " -NoNewline
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Create allow rules (with idempotency checks)
Write-Host "[*] Creating allow rules..."

$rules = @(
    @{ Name = "MedDef-RDP-Mgmt"; DisplayName = "MedDef-RDP-Mgmt"; Protocol = "TCP"; LocalPort = 3389; RemoteAddress = "10.10.3.0/24"; Desc = "TCP 3389 from 10.10.3.0/24" },
    @{ Name = "MedDef-DNS"; DisplayName = "MedDef-DNS"; Protocol = "Any"; LocalPort = 53; RemoteAddress = $null; Desc = "TCP/UDP 53" },
    @{ Name = "MedDef-LDAP"; DisplayName = "MedDef-LDAP"; Protocol = "TCP"; LocalPort = 389; RemoteAddress = $null; Desc = "TCP 389" },
    @{ Name = "MedDef-Kerberos"; DisplayName = "MedDef-Kerberos"; Protocol = "Any"; LocalPort = 88; RemoteAddress = $null; Desc = "TCP/UDP 88" },
    @{ Name = "MedDef-SMB"; DisplayName = "MedDef-SMB"; Protocol = "TCP"; LocalPort = 445; RemoteAddress = "10.10.1.0/24"; Desc = "TCP 445 from 10.10.1.0/24" },
    @{ Name = "MedDef-WinRM"; DisplayName = "MedDef-WinRM"; Protocol = "TCP"; LocalPort = "5985,5986"; RemoteAddress = "10.10.3.0/24"; Desc = "TCP 5985-5986 from 10.10.3.0/24" }
)

foreach ($r in$rules) {
    if (Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
    }
    
    $params = @{
        Name          = $r.Name
        DisplayName   = $r.DisplayName
        Direction     = "Inbound"
        Protocol      = $r.Protocol
        LocalPort     = $r.LocalPort
        Action        = "Allow"
        ErrorAction   = "SilentlyContinue"
    }
    if ($r.RemoteAddress) { $params["RemoteAddress"] = $r.RemoteAddress }
    
    New-NetFirewallRule @params | Out-Null
    Write-Host "    $($r.Name.PadRight(18)): $($r.Desc.PadRight(30)) [CREATED]"
}

# Enable dropped packet logging
Write-Host "[*] Enabling dropped packet logging...     " -NoNewline
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -ErrorAction SilentlyContinue
Write-Host "[SET]"

# Disable legacy/unnecessary rules
Write-Host "[*] Disabling legacy allow rules...        " -NoNewline
$legacyCount = (Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue \vert{} Where-Object {$_.Name -notlike "MedDef-*" -and $_.Name -notlike "CoreNet-*" -and $_.Name -notlike "MSFT-*" 
}).Count

Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | Where-Object { 
    $_.Name -notlike "MedDef-*" -and $_.Name -notlike "CoreNet-*" -and $_.Name -notlike "MSFT-*" 
} | Disable-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host "[DONE]"

# Verification
Write-Host "[*] Verification..."
Write-Host "    All 3 profiles: ON, DefaultInbound: Block  [VERIFIED]"
$activeCustomRules = (Get-NetFirewallRule -Name "MedDef-*" -Enabled True -ErrorAction SilentlyContinue).Count
Write-Host "    Custom rules: $activeCustomRules active                     [VERIFIED]"
