#!/bin/bash
# name: 2-pre_patch_snapshot.sh
# purpose: Captures the complete pre-patch system state into pre_patch_state.json with high performance.
# author: Massimo Rios

set -euo pipefail

OUTPUT_FILE="pre_patch_state.json"


for cmd in jq dpkg systemctl ss sha256sum awk sed hostname uname; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

# Metadata, Kernel, and Host Details
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOST_NAME=$(hostname)
KERNEL_RELEASE=$(uname -r)

REBOOT_REQUIRED=false
if [ -f "/var/run/reboot-required" ]; then
    REBOOT_REQUIRED=true
fi

# Package Versions Collection (Optimized single-pass jq streaming)
pkg_tmp=$(mktemp)
dpkg-query -W -f='${Package}\t${Version}\n' > "$pkg_tmp"
package_count=$(wc -l < "$pkg_tmp")

PACKAGES_JSON=$(jq -R -s '
    [split("\n")[] | select(length > 0) | split("\t") | {key: .[0], value: .[1]}] | from_entries
' < "$pkg_tmp")
rm -f "$pkg_tmp"

# Active Services State Collection (Optimized single-pass jq streaming)
srv_tmp=$(mktemp)
service_count=0

while read -r service; do
    [ -z "$service" ] && continue
    service_count=$((service_count + 1))
    
    active_state=$(systemctl show -p ActiveState --value "$service" 2>/dev/null || echo "unknown")
    sub_state=$(systemctl show -p SubState --value "$service" 2>/dev/null || echo "unknown")
    main_pid=$(systemctl show -p MainPID --value "$service" 2>/dev/null || echo "0")
    
    printf "%s\t%s\t%s\t%s\n" "$service" "$active_state" "$sub_state" "$main_pid" >> "$srv_tmp"
done < <(systemctl list-units --type=service --state=active --no-legend --no-pager | awk '{print $1}')

SERVICES_JSON=$(jq -R -s '
    [split("\n")[] | select(length > 0) | split("\t") | {
        key: .[0],
        value: {active_state: .[1], sub_state: .[2], main_pid: (.[3] | tonumber)}
    }] | from_entries
' < "$srv_tmp")
rm -f "$srv_tmp"

# Listening Sockets Collection
LISTENING_ARRAY=()
while IFS= read -r line; do
    [ -n "$line" ] && LISTENING_ARRAY+=("$line")
done < <(ss -tulnp 2>/dev/null)

LISTENING_JSON=$(jq -nc '$ARGS.positional' --args "${LISTENING_ARRAY[@]}")

#  Configuration File Hashes under /etc Tracked by Packages (Optimized buffering)
conffile_tmp=$(mktemp)
conffile_count=0

while read -r conf_path; do
    if [ -f "$conf_path" ]; then
        hash_val=$(sha256sum "$conf_path" 2>/dev/null | awk '{print $1}')
        if [ -n "$hash_val" ]; then
            printf "%s\t%s\n" "$conf_path" "$hash_val" >> "$conffile_tmp"
            conffile_count=$((conffile_count + 1))
        fi
    fi
done < <(dpkg-query -W -f='${Conffiles}\n' | awk '{print $1}' | grep '^/etc/' | sort -u)

CONFFILES_JSON=$(jq -R -s '
    [split("\n")[] | select(length > 0) | split("\t") | {key: .[0], value: .[1]}] | from_entries
' < "$conffile_tmp")
rm -f "$conffile_tmp"

# 6. Assemble Final Snapshot JSON
jq -n \
    --arg ts "$TIMESTAMP" \
    --arg hn "$HOST_NAME" \
    --arg kr "$KERNEL_RELEASE" \
    --argjson pkg_cnt "$package_count" \
    --argjson srv_cnt "$service_count" \
    --argjson pkgs "$PACKAGES_JSON" \
    --argjson srvs "$SERVICES_JSON" \
    --argjson list "$LISTENING_JSON" \
    --argjson confs "$CONFFILES_JSON" \
    --argjson reboot "$REBOOT_REQUIRED" \
    '{
        timestamp: $ts,
        hostname: $hn,
        kernel: $kr,
        packages: $pkg_cnt,
        services: $srv_cnt,
        package_details: $pkgs,
        service_details: $srvs,
        listening: $list,
        conffile_hashes: $confs,
        reboot_required: $reboot
    }' > "$OUTPUT_FILE"

# Calculate file size in KB for output summary
file_size_kb=$(du -k "$OUTPUT_FILE" | cut -f1)

# Display required summary output format
echo "Snapshot: $OUTPUT_FILE"
echo "Size: ${file_size_kb} KB"
echo "Kernel: $KERNEL_RELEASE"
echo "Reboot required: $REBOOT_REQUIRED"
