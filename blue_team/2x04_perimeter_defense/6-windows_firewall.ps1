<#
.SYNOPSIS
    Aligns Windows Firewall profiles and rules with the MedDefense segmentation contract.
.NAME
    6-windows_firewall.ps1
.DESCRIPTION
    Reads segmentation_rules.json, configures firewall profile defaults and block logging,
    cleans up prior MedDefense rules for idempotency, and creates inbound rules based on the flow matrix, jq
.AUTHOR
    Massimo
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RulesJsonPath = "segmentation_rules.json"

Write-Host "[*] Reading ${RulesJsonPath}..." -ForegroundColor Cyan
if (-not (Test-Path $RulesJsonPath)) {
    Write-Error "[-] Error: ${RulesJsonPath} not found. Please ensure it is in the current directory."
    exit 1
}

$JsonContent = Get-Content -Path $RulesJsonPath -Raw | ConvertFrom-Json

Write-Host "[*] Setting profile defaults..." -ForegroundColor Cyan
$Profiles = @("Domain", "Private", "Public")
$LogPath = "$env:systemroot\system32\LogFiles\Firewall\meddefense.log"

foreach ($Profile in $Profiles) {
    Set-NetFirewallProfile -Profile $Profile -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName $LogPath
    Write-Host "  ${Profile}:  DefaultInboundAction=Block  LogBlocked=True   [SET]"
}

Write-Host "[*] Clearing previous MedDefense-* rules..." -ForegroundColor Cyan
$ExistingRules = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$RemovedCount = 0
if ($ExistingRules) {
    $RemovedCount = @($ExistingRules).Count
    $ExistingRules | Remove-NetFirewallRule
}
Write-Host "  [${RemovedCount} removed]" -ForegroundColor Green

Write-Host "[*] Creating rules from flow matrix..." -ForegroundColor Cyan

$ZoneCidrs = @{}
foreach ($Zone in $JsonContent.zones) {
    $ZoneCidrs[$Zone.name] = $Zone.cidr
}

# Iterate through flows and create rules for flows terminating on local host or matching inbound requirements
foreach ($Flow in $JsonContent.flows) {
    if ($Flow.dst_zone -eq "INTERNAL" -or $Flow.dst_zone -eq "DMZ" -or $Flow.dst_zone -eq "MGMT" -or $Flow.dst_zone -eq "MEDDEV") {
        $RemoteAddr = "Any"
        if ($ZoneCidrs.ContainsKey($Flow.src_zone)) {
            $RemoteAddr = $ZoneCidrs[$Flow.src_zone]
        } elseif ($Flow.src_zone -eq "ANY") {
            $RemoteAddr = "Any"
        }

        $DisplayName = "MedDefense-$($Flow.src_zone)-$($Flow.proto.ToUpper())-$($Flow.dport)"
        
        # Avoid duplicate rule creation if multiple flows share the exact same signature
        $CheckExisting = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if (-not $CheckExisting) {
            New-NetFirewallRule -DisplayName $DisplayName `
                                -Direction Inbound `
                                -Action Allow `
                                -Protocol $Flow.proto `
                                -LocalPort $Flow.dport `
                                -RemoteAddress $RemoteAddr `
                                -Profile Any | Out-Null
            
            Write-Host "  $DisplayName".PadLeft(32).PadRight(44) "Inbound Allow $($Flow.proto) $($Flow.dport)".PadLeft(26) "  [CREATED]" -ForegroundColor Green
        }
    }
}

Write-Host "[+] Windows Firewall alignment completed successfully." -ForegroundColor Cyan
