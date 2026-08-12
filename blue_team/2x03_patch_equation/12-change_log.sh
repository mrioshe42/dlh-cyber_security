#!/bin/bash
# name: 12-change_log.sh
# purpose: Canonical change tracking log generator parsing apt history and producing patch_change_log.json.
# 11-maintenance_window.sh 

set -uo pipefail

LOG_DIR="/var/log/apt"
OUTPUT_FILE="patch_change_log.json"
WINDOW_CONFIG="maintenance_windows.json"
EXEC_LOG="patch_execution_log.json"
VULN_INV="vulnerability_inventory.json"

if [ ! -d "$LOG_DIR" ]; then
    echo "Error: $LOG_DIR not found." >&2
    exit 1
fi

TMP_TRANS="/tmp/apt_transactions_$$.tmp"
rm -f "$TMP_TRANS"

to_mins() {
    local hm="$1"
    local h="${hm%%:*}"
    local m="${hm##*:}"
    echo $(( 10#$h * 60 + 10#$m ))
}

# Parse all apt history logs (including rotated and gzipped) /var/log/apt/history.log Upgrade: Install: Remove: 15
for log in "$LOG_DIR"/history.log*; do
    [ -e "$log" ] || continue
    if [[ "$log" == *.gz ]]; then
        zcat "$log" 2>/dev/null
    else
        cat "$log" 2>/dev/null
    fi
done | awk '
BEGIN { RS=""; FS="\n" }
{
    start_date = ""; cmd = ""; req_by = ""; pkgs = 0;
    for (i=1; i<=NF; i++) {
        if ($i ~ /^Start-Date:/) {
            sub(/^Start-Date:[ \t]*/, "", $i);
            start_date = $i;
        } else if ($i ~ /^Commandline:/) {
            sub(/^Commandline:[ \t]*/, "", $i);
            cmd = $i;
        } else if ($i ~ /^Requested-By:/) {
            sub(/^Requested-By:[ \t]*/, "", $i);
            req_by = $i;
        } else if ($i ~ /^(Upgrade|Install|Remove):/) {
            line = $i;
            sub(/^[^:]*:[ \t]*/, "", line);
            n = split(line, arr, ",");
            pkgs += n;
        }
    }
    if (start_date != "") {
        gsub(/^[ \t]+|[ \t]+$/, "", start_date);
        print start_date "|" req_by "|" pkgs "|" cmd;
    }
}' | sort -u > "$TMP_TRANS"
# change event
events_json="[]"
total_events=0
inside_window_count=0
outside_window_count=0
cves_resolved_count=0

period_start=""
period_end=""

# Read transactions and evaluate window status
while IFS='|' read -r t_date t_user t_pkgs t_cmd; do
    [ -z "$t_date" ] && continue
    
    epoch=$(date -d "$t_date" +%s 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$t_date" +%s 2>/dev/null || echo "0")
    [ "$epoch" -eq 0 ] && continue

    iso_date=$(date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ")
    if [ -z "$period_start" ]; then
        period_start="$iso_date"
    fi
    period_end="$iso_date"

    clean_user=$(echo "$t_user" | awk '{print $1}')
    [ -z "$clean_user" ] && clean_user="root"

    # Time window calculation using numeric minute comparison
    dow=$(date -d "@$epoch" +"%a" 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$t_date" +"%a" 2>/dev/null || echo "Mon")
    hm=$(date -d "@$epoch" +"%H:%M" 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$t_date" +"%H:%M" 2>/dev/null || echo "10:00")
    
    within_status="outside"
    if [ "$dow" = "Sat" ]; then
        hm_mins=$(to_mins "$hm")
        if [ "$hm_mins" -ge 120 ] && [ "$hm_mins" -le 360 ]; then
            within_status="inside"
        fi
    fi

    if [ "$within_status" = "inside" ]; then
        inside_window_count=$((inside_window_count + 1))
    else
        outside_window_count=$((outside_window_count + 1))
    fi
    total_events=$((total_events + 1))

    iso_started=$(date -d "@$epoch" +"%Y-%m-%dT%H:%M:%S%:z" 2>/dev/null || date -j -f "%Y-%m-%d %H:%M:%S" "$t_date" +"%Y-%m-%dT%H:%M:%S%z" 2>/dev/null || echo "$t_date")

    # Linked execution log check
    linked_log="null"
    if [ -f "$EXEC_LOG" ]; then
        linked_log="\"$EXEC_LOG\""
    fi

    events_json=$(echo "$events_json" | jq \
        --arg st "$iso_started" \
        --arg u "$clean_user" \
        --arg ww "$within_status" \
        --argjson pkg "$t_pkgs" \
        --argjson exec_log "$linked_log" \
        '. + [{
            started: $st,
            user: $u,
            within_window: $ww,
            packages: $pkg,
            linked_execution_log: $exec_log
        }]')

done < "$TMP_TRANS"

rm -f "$TMP_TRANS"

if [ -f "$VULN_INV" ]; then
    cves_resolved_count=$(jq '[.entries[]? | select(.status == "resolved")] | length' "$VULN_INV" 2>/dev/null || echo 0)
fi

jq -n \
    --arg ps "$period_start" \
    --arg pe "$period_end" \
    --argjson evts "$events_json" \
    --argjson te "$total_events" \
    --argjson iw "$inside_window_count" \
    --argjson ow "$outside_window_count" \
    --argjson cr "$cves_resolved_count" \
    '{
        period_start: $ps,
        period_end: $pe,
        events: $evts,
        summary: {
            total_events: $te,
            inside_window: $iw,
            outside_window: $ow,
            cves_resolved: $cr
        }
    }' > "$OUTPUT_FILE"

if [ -f "$OUTPUT_FILE" ]; then
    jq -c '.events[] | {started: .started, user: .user, within_window: .within_window, packages: .packages}' "$OUTPUT_FILE"
fi

exit 0
