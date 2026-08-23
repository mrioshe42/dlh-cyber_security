#!/bin/bash
# Script Name: 2-target_state.sh
# Description: Generates the machine-readable target_state.json contract defining
#              all control criteria for downstream validation and compliance. net.ipv4.ip_forward
# Exit Codes:  0 = Success, 1 = Controlled Failure, 2 = Environment Error

set -uo pipefail
# capstone/target_state.json
CAPSTONE_DIR="./capstone"
TARGET_JSON="${CAPSTONE_DIR}/target_state.json"
FORCE_FLAG=false

for arg in "$@"; do
    if [ "$arg" == "--force" ]; then
        FORCE_FLAG=true
    fi
done

if ! mkdir -p "$CAPSTONE_DIR"; then
    echo "[-] Error: Failed to create directory $CAPSTONE_DIR" >&2
    exit 2
fi

if ! command -v jq &>/dev/null; then
    echo "[-] Error: Required dependency 'jq' is missing." >&2
    exit 2
fi

if [ -f "$TARGET_JSON" ] && [ "$FORCE_FLAG" = false ]; then
    echo "[-] Error: $TARGET_JSON already exists. Use '--force' to overwrite." >&2
    exit 1
fi

echo "[+] Generating target state definition contract..."

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCHEMA_VERSION="1.0.0"

jq -n \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg generated_at "$TIMESTAMP" \
    '{
        schema_version: $schema_version,
        generated_at: $generated_at,
        controls: [
            {
                id: "LNX-SSH-01",
                platform: "linux",
                family: "hardening",
                description: "SSH must not permit root login",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^PermitRootLogin\\s+no",
                source_project: "2x00",
                severity: "critical"
            },
            {
                id: "LNX-SSH-02",
                platform: "linux",
                family: "hardening",
                description: "SSH must refuse password authentication",
                check_type: "grep_match",
                check_target: "/etc/ssh/sshd_config",
                expected_value: "^PasswordAuthentication\\s+no",
                source_project: "2x00",
                severity: "critical"
            },
            {
                id: "LNX-SYS-01",
                platform: "linux",
                family: "hardening",
                description: "Kernel IP forwarding must be disabled",
                check_type: "json_field_equals",
                check_target: "/proc/sys/net/ipv4/ip_forward",
                expected_value: "0",
                source_project: "2x00",
                severity: "high"
            },
            {
                id: "LNX-SYS-02",
                platform: "linux",
                family: "hardening",
                description: "Address space layout randomization must be fully enabled",
                check_type: "json_field_equals",
                check_target: "/proc/sys/kernel/randomize_va_space",
                expected_value: "2",
                source_project: "2x00",
                severity: "high"
            },
            {
                id: "LNX-AUD-01",
                platform: "linux",
                family: "telemetry",
                description: "Auditd service must be active and running",
                check_type: "command_exit_zero",
                check_target: "systemctl is-active --quiet auditd",
                expected_value: "0",
                source_project: "2x02",
                severity: "high"
            },
            {
                id: "LNX-APP-01",
                platform: "linux",
                family: "hardening",
                description: "AppArmor must be running in enforce mode",
                check_type: "command_exit_zero",
                check_target: "aa-status --enabled",
                expected_value: "0",
                source_project: "2x00",
                severity: "medium"
            },
            {
                id: "LNX-LYN-01",
                platform: "linux",
                family: "hardening",
                description: "Lynis hardening index must be at least 80",
                check_type: "json_field_gte",
                check_target: "capstone/baseline/baseline_linux.json:.hardening_index",
                expected_value: 80,
                source_project: "2x00",
                severity: "high"
            },
            {
                id: "WIN-FW-01",
                platform: "windows",
                family: "hardening",
                description: "Windows Firewall must default-deny inbound on every profile",
                check_type: "json_field_equals",
                check_target: "capstone/baseline/windows_firewall_status.json",
                expected_value: "Block",
                source_project: "2x01",
                severity: "critical"
            },
            {
                id: "WIN-LOG-01",
                platform: "windows",
                family: "telemetry",
                description: "PowerShell Script Block Logging must be enabled",
                check_type: "json_field_equals",
                check_target: "capstone/baseline/windows_intake_baseline.json:.Script_Block_Logging",
                expected_value: 1,
                source_project: "2x02",
                severity: "high"
            },
            {
                id: "WIN-SYM-01",
                platform: "windows",
                family: "telemetry",
                description: "Sysmon service must be installed and running",
                check_type: "command_exit_zero",
                check_target: "Get-Service -Name Sysmon -Status Running",
                expected_value: "0",
                source_project: "2x02",
                severity: "high"
            },
            {
                id: "WIN-AUD-01",
                platform: "windows",
                family: "telemetry",
                description: "Audit policy must cover Account Logon, Logon, Object Access and Privilege Use subcategories",
                check_type: "command_exit_zero",
                check_target: "auditpol /get /category:*",
                expected_value: "0",
                source_project: "2x02",
                severity: "medium"
            },
            {
                id: "WIN-CIS-01",
                platform: "windows",
                family: "hardening",
                description: "CIS Level 1 pass rate must be at least 85 percent",
                check_type: "json_field_gte",
                check_target: "capstone/baseline/baseline_windows.json:.Pass_Rate_Percent",
                expected_value: 85,
                source_project: "2x01",
                severity: "high"
            },
            {
                id: "TEL-LNX-01",
                platform: "linux",
                family: "telemetry",
                description: "Linux auditd rules file must be present and loaded",
                check_type: "file_exists",
                check_target: "/etc/audit/rules.d/audit.rules",
                expected_value: true,
                source_project: "2x02",
                severity: "medium"
            },
            {
                id: "TEL-EXP-01",
                platform: "both",
                family: "telemetry",
                description: "Structured JSON export path must exist",
                check_type: "file_exists",
                check_target: "capstone/telemetry/",
                expected_value: true,
                source_project: "2x02",
                severity: "high"
            },
            {
                id: "TEL-SYM-02",
                platform: "windows",
                family: "telemetry",
                description: "Windows Sysmon event count must be greater than zero in the last 10 minutes",
                check_type: "json_field_gte",
                check_target: "capstone/telemetry/sysmon_count.json:.event_count",
                expected_value: 1,
                source_project: "2x02",
                severity: "high"
            },
            {
                id: "TEL-SBL-01",
                platform: "windows",
                family: "telemetry",
                description: "Script Block Logging event channel size must be greater than zero",
                check_type: "json_field_gte",
                check_target: "capstone/telemetry/sbl_size.json:.channel_size",
                expected_value: 1,
                source_project: "2x02",
                severity: "medium"
            },
            {
                id: "PAT-INV-01",
                platform: "both",
                family: "patching",
                description: "vulnerability_inventory.json must be present",
                check_type: "file_exists",
                check_target: "capstone/patching/vulnerability_inventory.json",
                expected_value: true,
                source_project: "2x03",
                severity: "high"
            },
            {
                id: "PAT-PLN-01",
                platform: "both",
                family: "patching",
                description: "patch_plan.json must be present",
                check_type: "file_exists",
                check_target: "capstone/patching/patch_plan.json",
                expected_value: true,
                source_project: "2x03",
                severity: "high"
            },
            {
                id: "PAT-LOG-01",
                platform: "both",
                family: "patching",
                description: "patch_execution_log.json must be present with zero entries in failed state",
                check_type: "file_exists",
                check_target: "capstone/patching/patch_execution_log.json",
                expected_value: true,
                source_project: "2x03",
                severity: "critical"
            },
            {
                id: "PAT-UPG-01",
                platform: "linux",
                family: "patching",
                description: "unattended-upgrades must be configured with the mandated blacklist",
                check_type: "file_exists",
                check_target: "/etc/apt/apt.conf.d/50unattended-upgrades",
                expected_value: true,
                source_project: "2x03",
                severity: "medium"
            },
            {
                id: "NET-NFT-01",
                platform: "network",
                family: "network",
                description: "nftables input chain must default to drop",
                check_type: "grep_match",
                check_target: "/etc/nftables.conf",
                expected_value: "policy drop;",
                source_project: "2x04",
                severity: "critical"
            },
            {
                id: "NET-SEG-01",
                platform: "network",
                family: "network",
                description: "segmentation_rules.json must be present",
                check_type: "file_exists",
                check_target: "capstone/network/segmentation_rules.json",
                expected_value: true,
                source_project: "2x04",
                severity: "high"
            },
            {
                id: "NET-SUR-01",
                platform: "network",
                family: "network",
                description: "Suricata custom rule file must be loaded with at least six rules",
                check_type: "grep_match",
                check_target: "/etc/suricata/rules/custom.rules",
                expected_value: "^alert.*",
                source_project: "2x04",
                severity: "high"
            },
            {
                id: "NET-VAL-01",
                platform: "network",
                family: "network",
                description: "Suricata rule validation report must show every rule fired against its target PCAP",
                check_type: "file_exists",
                check_target: "capstone/network/suricata_validation_report.json",
                expected_value: true,
                source_project: "2x04",
                severity: "medium"
            },
            {
                id: "NET-DNS-01",
                platform: "network",
                family: "network",
                description: "DNS filter must be active",
                check_type: "command_exit_zero",
                check_target: "systemctl is-active --quiet pihole-FTL",
                expected_value: "0",
                source_project: "2x04",
                severity: "high"
            },
            {
                id: "HAN-CMP-01",
                platform: "both",
                family: "handoff",
                description: "compliance.json must be present",
                check_type: "file_exists",
                check_target: "capstone/compliance.json",
                expected_value: true,
                source_project: "handoff",
                severity: "critical"
            },
            {
                id: "HAN-MAN-01",
                platform: "both",
                family: "handoff",
                description: "manifest.json must be present with SHA-256 per file",
                check_type: "file_exists",
                check_target: "capstone/manifest.json",
                expected_value: true,
                source_project: "handoff",
                severity: "critical"
            },
            {
                id: "HAN-PKG-01",
                platform: "both",
                family: "handoff",
                description: "Telemetry export package must exist and be tarballed",
                check_type: "file_exists",
                check_target: "capstone/telemetry_export.tar.gz",
                expected_value: true,
                source_project: "handoff",
                severity: "high"
            },
            {
                id: "HAN-RUN-01",
                platform: "both",
                family: "handoff",
                description: "Runbook script must be present and executable",
                check_type: "file_exists",
                check_target: "capstone/runbook.sh",
                expected_value: true,
                source_project: "handoff",
                severity: "high"
            }
        ]
    }' > "$TARGET_JSON"

if [ -f "$TARGET_JSON" ]; then
    echo "[+] Target state contract successfully generated at $TARGET_JSON"
    exit 0
else
    echo "[-] Error: Failed to write target_state.json" >&2
    exit 1
fi
