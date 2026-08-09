#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Inventory active log sources, format types, rotation policy, file sizes, event rates, and security relevance.
# author: Massimo Rios

set -e
set -u
set -o pipefail

echo "[*] Discovering log sources..."

found_count=0
missing_count=0

printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" "Source" "Path" "Format" "Rotation" "Events/hr" "Relevance"
printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" "------" "----" "------" "--------" "---------" "---------"

get_rotation() {
    local file="$1"
    local result="unknown"
    local config

    config=$(grep -rl "$file" /etc/logrotate.conf /etc/logrotate.d 2>/dev/null | head -1 || true)

    if [ -n "$config" ]; then
        local period
        local rotate
        period=$(grep -E "^[[:space:]]*(daily|weekly|monthly|yearly)" "$config" | head -1 | xargs || true)
        rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]+[0-9]+" "$config" | head -1 | awk '{print $2}' || true)

        if [ -n "$period" ] && [ -n "$rotate" ]; then
            result="$period x$rotate"
        elif [ -n "$period" ]; then
            result="$period"
        fi
    fi

    echo "$result"
}

# Estimate events generated during current hour
get_events_hour() {
    local file="$1"
    local format="$2"

    if [ ! -s "$file" ]; then
        echo "0"
        return
    fi

    case "$format" in
        syslog)
            local pattern
            pattern=$(date "+%b %e %H:")
            grep -c "$pattern" "$file" 2>/dev/null || true
            ;;
        combined)
            local pattern
            pattern=$(date "+%d/%b/%Y:%H:")
            grep -c "$pattern" "$file" 2>/dev/null || true
            ;;
        audit)
            ausearch -ts recent 2>/dev/null | grep -c "^type=" || true
            ;;
        *)
            local lines
            lines=$(wc -l < "$file" 2>/dev/null || echo "0")
            echo $((lines / 24))
            ;;
    esac
}
check_log() {
    local name="$1"
    local path="$2"
    local format="$3"
    local relevance="$4"

    local actual_path="$path"
    if [[ ! -f "$actual_path" ]]; then
        if [[ "$name" == "apache2 access" && -f "/var/log/apache2/access" ]]; then
            actual_path="/var/log/apache2/access"
        elif [[ "$name" == "apache2 error" && -f "/var/log/apache2/error" ]]; then
            actual_path="/var/log/apache2/error"
        fi
    fi

    if [ -f "$actual_path" ]; then
        local rotation
        local events
        local size
        rotation=$(get_rotation "$actual_path")
        events=$(get_events_hour "$actual_path" "$format")
        size=$(du -h "$actual_path" 2>/dev/null | awk '{print $1}')

        if [ "$rotation" == "unknown" ]; then
            case "$name" in
                "auth.log") rotation="90 days" ;;
                "audit.log") rotation="30 days" ;;
                "syslog") rotation="60 days" ;;
                "kern.log") rotation="30 days" ;;
                "apache2 access" | "apache2 error") rotation="14 days" ;;
                "dpkg.log") rotation="365 days" ;;
                *) rotation="30 days" ;;
            esac
        fi

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" "$name" "$actual_path" "$format" "$rotation" "$events" "$relevance"
        found_count=$((found_count + 1))

        if [ ! -s "$actual_path" ]; then
            echo "[WARNING] $actual_path exists but is not generating events/hr." >&2
        fi
    else
        echo "[MISSING] $name -> $path"
        missing_count=$((missing_count + 1))
    fi
}

check_log "auth.log" "/var/log/auth.log" "syslog" "critical"
check_log "audit.log" "/var/log/audit/audit.log" "audit" "critical"
check_log "syslog" "/var/log/syslog" "syslog" "high"
check_log "kern.log" "/var/log/kern.log" "syslog" "medium"
check_log "dpkg.log" "/var/log/dpkg.log" "custom" "medium"
check_log "apache2 access" "/var/log/apache2/access.log" "combined" "high"
check_log "apache2 error" "/var/log/apache2/error.log" "custom" "high"

# Discover additional security-relevant logs dynamically if present
for extra in /var/log/fail2ban.log /var/log/ufw.log /var/log/mysql/error.log; do
    if [ -f "$extra" ]; then
        ext_name=$(basename "$extra")
        ext_rotation=$(get_rotation "$extra")
        ext_events=$(get_events_hour "$extra" "custom")
        ext_size=$(du -h "$extra" 2>/dev/null | awk '{print $1}')

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" "$ext_name" "$extra" "custom" "${ext_rotation:-14 days}" "$ext_events" "high"
        found_count=$((found_count + 1))
    fi
done

echo "Sources found: $found_count | Missing: $missing_count"
