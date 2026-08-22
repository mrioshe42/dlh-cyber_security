#!/bin/bash
# Script Name: 0-environment_intake.sh
# Description: Captures the unhardened raw baseline state of hawthorne-app-01
#              into a structured JSON artifact for delta comparison. Sysmon 

set -uo pipefail

OUTPUT_DIR="./evidence"
OUTPUT_FILE="${OUTPUT_DIR}/linux_intake_baseline.json"

if ! mkdir -p "$OUTPUT_DIR"; then
    echo "[-] Error: Failed to create output directory $OUTPUT_DIR" >&2
    exit 2
fi

for cmd in jq ss systemctl dpkg-query find; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[-] Error: Required dependency '$cmd' is missing." >&2
        exit 2
    fi
done

echo "[+] Starting Linux environment intake on $(hostname)..."

HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
KERNEL_REL=$(uname -r)
DISTRO=$(. /etc/os-release && echo "$PRETTY_NAME")
PKG_COUNT=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | wc -l)
LISTENING_SOCKETS=$(ss -tulnpH 2>/dev/null | wc -l)
ACTIVE_SERVICES=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l)

# Parse sshd_config safely into JSON-friendly format net.ipv4.ip_forward kernel.randomize_va_space
if [ -f /etc/ssh/sshd_config ]; then
    SSHD_CONF=$(grep -E '^[A-Za-z]' /etc/ssh/sshd_config | awk '{print "\"" $1 "\": \"" $2 "\""}' | paste -sd, -)
    SSHD_JSON="{${SSHD_CONF}}"
else
    SSHD_JSON="{}"
fi

SYSCTL_VAL=$(sysctl -a 2>/dev/null | head -n 50 | awk -F' = ' '{print "\"" $1 "\": \"" $2 "\""}' | paste -sd, -)
SYSCTL_JSON="{${SYSCTL_VAL:-}}"
SUID_COUNT=$(find / -perm /6000 -type f 2>/dev/null | wc -l)
WW_COUNT=$(find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f 2>/dev/null | wc -l)
NFT_RULES=0

if command -v nft &>/dev/null; then
    NFT_RULES=$(nft list ruleset 2>/dev/null | wc -l)
fi

# Telemetry presence checks
AUDITD_STATUS=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
RSYSLOG_STATUS=$(systemctl is-active rsyslog 2>/dev/null || echo "inactive")
SYSMON_STATUS=$(systemctl is-active sysmon 2>/dev/null || echo "inactive")

jq -n \
    --arg hostname "$HOSTNAME_VAL" \
    --arg kernel "$KERNEL_REL" \
    --arg distro "$DISTRO" \
    --argjson pkg_count "$PKG_COUNT" \
    --argjson sockets "$LISTENING_SOCKETS" \
    --argjson services "$ACTIVE_SERVICES" \
    --argjson sshd "$SSHD_JSON" \
    --argjson sysctl "$SYSCTL_JSON" \
    --argjson suid_count "$SUID_COUNT" \
    --argjson ww_count "$WW_COUNT" \
    --argjson nft_rules "$NFT_RULES" \
    --arg auditd "$AUDITD_STATUS" \
    --arg rsyslog "$RSYSLOG_STATUS" \
    --arg sysmon "$SYSMON_STATUS" \
    '{
        timestamp: (now | todate),
        hostname: $hostname,
        kernel: $kernel,
        distribution: $distro,
        package_count: $pkg_count,
        listening_sockets: $sockets,
        active_services: $services,
        sshd_config: $sshd,
        sysctl_sample: $sysctl,
        suid_sgid_count: $suid_count,
        world_writable_count: $ww_count,
        nft_ruleset_lines: $nft_rules,
        telemetry: {
            auditd: $auditd,
            rsyslog: $rsyslog,
            sysmon_linux: $sysmon
        }
    }' > "$OUTPUT_FILE"

if [ -f "$OUTPUT_FILE" ]; then
    echo "[+] Linux intake complete. Evidence saved to $OUTPUT_FILE"
    exit 0
else
    echo "[-] Error: Failed to write output file." >&2
    exit 1
fi
