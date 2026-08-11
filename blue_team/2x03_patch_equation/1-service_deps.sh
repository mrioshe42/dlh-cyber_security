#!/bin/bash
# name: 1-service_deps.sh
# purpose: Maps systemd services to binaries, owning packages, linked libraries, and criticality.
# author: Massimo Rios
set -euo pipefail

OUTPUT_FILE="service_dependency_map.json"
CRITICALITY_FILE="service_criticality.json"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

if [ ! -f "$CRITICALITY_FILE" ]; then
    echo '{"apache2.service": "critical", "ssh.service": "critical", "postgresql.service": "high"}' > "$CRITICALITY_FILE"
fi

TEMP_SERVICES=$(mktemp)
JSON_ENTRIES=$(mktemp)

trap 'rm -f "$TEMP_SERVICES" "$JSON_ENTRIES"' EXIT

# Enumerate active systemd services
systemctl list-units --type=service --state=active --no-legend --no-pager | awk '{print $1}' > "$TEMP_SERVICES"

echo "[" > "$JSON_ENTRIES"
FIRST=1

while IFS= read -r service; do
    [ -z "$service" ] && continue

    # Resolve executable path from ExecStart or MainPID
    exec_path=""
    exec_start_line=$(systemctl show -p ExecStart --value "$service" 2>/dev/null || true)
    
    if [[ "$exec_start_line" =~ path=([^ ;]+) ]]; then
        exec_path="${BASH_REMATCH[1]}"
    fi

    if [ -z "$exec_path" ] || [ ! -x "$exec_path" ]; then
        main_pid=$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)
        if [ -n "$main_pid" ] && [ "$main_pid" -gt 0 ] && [ -e "/proc/$main_pid/exe" ]; then
            exec_path=$(readlink -f "/proc/$main_pid/exe" 2>/dev/null || true)
        fi
    fi

    [ -z "$exec_path" ] || [ ! -e "$exec_path" ] && continue

    # Resolve owning package via dpkg -S
    owning_package="unknown"
    dpkg_output=$(dpkg -S "$exec_path" 2>/dev/null || true)
    if [ -n "$dpkg_output" ]; then
        owning_package=$(echo "$dpkg_output" | cut -d':' -f1 | head -n1)
    fi

    # Resolve dynamic library dependencies with ldd and dpkg -S
    linked_pkgs=()
    if [ -f "$exec_path" ] && file "$exec_path" | grep -q "ELF"; then
        ldd_output=$(ldd "$exec_path" 2>/dev/null || true)
        while IFS= read -r ldd_line; do
            # Extract library absolute path
            if [[ "$ldd_line" =~ =>[[:space:]](/[^[:space:]]+) ]]; then
                lib_path="${BASH_REMATCH[1]}"
                if [ -e "$lib_path" ]; then
                    lib_pkg_out=$(dpkg -S "$lib_path" 2>/dev/null || true)
                    if [ -n "$lib_pkg_out" ]; then
                        lib_pkg=$(echo "$lib_pkg_out" | cut -d':' -f1 | head -n1)
                        if [[ ! " ${linked_pkgs[*]} " =~ " ${lib_pkg} " ]]; then
                            linked_pkgs+=("$lib_pkg")
                        fi
                    fi
                fi
            fi
        done <<< "$ldd_output"
    fi

    if [ "$owning_package" != "unknown" ] && [[ ! " ${linked_pkgs[*]} " =~ " ${owning_package} " ]]; then
        linked_pkgs+=("$owning_package")
    fi

    linked_json="[]"
    if [ ${#linked_pkgs[@]} -gt 0 ]; then
        linked_json=$(jq -nc '$ARGS.positional' --args "${linked_pkgs[@]}")
    fi

    # Tag criticality from service_criticality.json (default: low)
    criticality="low"
    if jq -e --arg s "$service" 'has($s)' "$CRITICALITY_FILE" >/dev/null 2>&1; then
        criticality=$(jq -r --arg s "$service" '.[$s]' "$CRITICALITY_FILE")
    fi

    restart_required=true
    [ "$criticality" = "low" ] && restart_required=false

    service_json=$(jq -nc \
        --arg s "$service" \
        --arg ep "$exec_path" \
        --arg op "$owning_package" \
        --argjson lp "$linked_json" \
        --arg crit "$criticality" \
        --argjson rr "$restart_required" \
        '{
            service: $s,
            exec_path: $ep,
            owning_package: $op,
            linked_packages: $lp,
            criticality: $crit,
            restart_required_on_patch: $rr
        }')

    if [ $FIRST -eq 0 ]; then
        echo "," >> "$JSON_ENTRIES"
    fi
    echo "$service_json" >> "$JSON_ENTRIES"
    FIRST=0

done < "$TEMP_SERVICES"

echo "]" >> "$JSON_ENTRIES"
jq '.' "$JSON_ENTRIES" > "$OUTPUT_FILE"

echo "Service dependency map successfully generated at $OUTPUT_FILE"
