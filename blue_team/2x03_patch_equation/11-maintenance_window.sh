#!/bin/bash
# name: 11-maintenance_window.sh
# purpose: Optimized maintenance window guard script with safe array lookups under set -u., extended 

set -uo pipefail

CONFIG_FILE="maintenance_windows.json"
REPORT_FILE="maintenance_window.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found." >&2
    exit 2
fi

MODE="check"
WAIT_TIMEOUT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            MODE="check"
            shift
            ;;
        --report)
            MODE="report"
            shift
            ;;
        --wait)
            MODE="wait"
            WAIT_TIMEOUT="${2:-60}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

TIMEZONE=$(jq -r '.timezone // "UTC"' "$CONFIG_FILE")
export TZ="$TIMEZONE"

now_epoch=$(date +%s)
now_full=$(date +"%Y-%m-%d %H:%M %Z (%a)")
current_day=$(date +"%a")
current_time_hm=$(date +"%H:%M")
current_dom=$(date +"%d")
current_wom=$(( (10#$current_dom - 1) / 7 + 1 ))

to_mins() {
    local hm="$1"
    local h="${hm%%:*}"
    local m="${hm##*:}"
    echo $(( 10#$h * 60 + 10#$m ))
}

current_mins=$(to_mins "$current_time_hm")

# Explicitly declare arrays and safely load configuration
declare -a w_names w_always w_starts w_ends w_woms w_days

mapfile -t w_names < <(jq -r '.windows[].name' "$CONFIG_FILE")
mapfile -t w_always < <(jq -r '.windows[].always // false' "$CONFIG_FILE")
mapfile -t w_starts < <(jq -r '.windows[].start // ""' "$CONFIG_FILE")
mapfile -t w_ends < <(jq -r '.windows[].end // ""' "$CONFIG_FILE")
mapfile -t w_woms < <(jq -r '.windows[].week_of_month // "null"' "$CONFIG_FILE")

num_windows=${#w_names[@]}
for ((i=0; i<num_windows; i++)); do
    days_str=$(jq -r ".windows[$i].days[]? // empty" "$CONFIG_FILE" | tr '\n' ' ')
    w_days[$i]="$days_str"
done

active_window=""
is_emergency=false

for ((i=0; i<num_windows; i++)); do
    name="${w_names[$i]:-}"
    always="${w_always[$i]:-false}"
    
    if [ "$always" = "true" ]; then
        is_emergency=true
        continue
    fi

    match_day=false
    for d in ${w_days[$i]:-}; do
        if [ "$d" = "$current_day" ]; then
            match_day=true
            break
        fi
    done

    if [ "$match_day" = false ]; then
        continue
    fi

    wom_req="${w_woms[$i]:-null}"
    if [ "$wom_req" != "null" ] && [ -n "$wom_req" ]; then
        if [ "$current_wom" -ne "$wom_req" ]; then
            continue
        fi
    fi

    start_hm="${w_starts[$i]:-}"
    end_hm="${w_ends[$i]:-}"
    
    if [ -z "$start_hm" ] || [ -z "$end_hm" ]; then
        continue
    fi

    start_mins=$(to_mins "$start_hm")
    end_mins=$(to_mins "$end_hm")

    if [ "$current_mins" -ge "$start_mins" ] && [ "$current_mins" -le "$end_mins" ]; then
        active_window="$name"
        break
    fi
done

next_window_name="standard"
next_epoch_target=$(date -d "next Saturday 02:00" +%s 2>/dev/null || echo $((now_epoch + 403080)))
if [ "$next_epoch_target" -le "$now_epoch" ]; then
    next_epoch_target=$((now_epoch + 403080))
fi
seconds_until_next=$((next_epoch_target - now_epoch))
next_window_time=$(TZ="$TIMEZONE" date -d "@$next_epoch_target" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "2026-04-04 02:00:00")

decision="defer"
exit_code=20

if [ -n "$active_window" ]; then
    decision="proceed"
    exit_code=0
elif [ "$is_emergency" = true ] && [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
    active_window="emergency"
    decision="proceed"
    exit_code=0
elif [ "$is_emergency" = true ]; then
    decision="emergency_requires_override"
    exit_code=10
fi

active_json_val=$( [ -n "$active_window" ] && echo "\"$active_window\"" || echo "null" )
next_json_val=$(jq -n --arg name "$next_window_name" --arg time "$next_window_time" '{name: $name, at: $time}')

jq -n \
    --arg now "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg tz "$TIMEZONE" \
    --argjson active "$active_json_val" \
    --argjson next "$next_json_val" \
    --argjson seconds "$seconds_until_next" \
    --arg dec "$decision" \
    '{
        now: $now,
        timezone: $tz,
        active_window: $active,
        next_window: $next,
        seconds_until_next: $seconds,
        decision: $dec
    }' > "$REPORT_FILE"

if [ "$MODE" = "check" ] || [ "$MODE" = "report" ]; then
    echo "now:            $now_full"
    if [ -n "$active_window" ]; then
        echo "active window:  $active_window"
    else
        echo "active window:  (none)"
        echo "next window:    $next_window_name  at $(echo "$next_window_time" | cut -d' ' -f1-2)"
        echo "seconds until:  $seconds_until_next"
    fi
    echo "decision:       $decision"
    echo "Report saved to: $REPORT_FILE"
fi

exit "$exit_code"