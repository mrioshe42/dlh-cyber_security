#!/bin/bash
# name: 4-patch_execute.sh
# purpose: Safely execute patches from patch_plan.json with robust JSON parsing, advisory locking, dpkg lock backoff, per-patch checks, and JSON logging.

set -uo pipefail

LOCK_FILE="/var/lock/meddefense-patch.lock"
PLAN_FILE="patch_plan.json"
LOG_FILE="patch_execution_log.json"

if [ ! -f "$PLAN_FILE" ]; then
    echo "Error: $PLAN_FILE not found." >&2
    exit 2
fi

# Acquire advisory lock with timeout/backoff simulation
echo -n "[*] Acquiring lock $LOCK_FILE...  "
exec 200> "$LOCK_FILE"
if ! flock -n 200; then
    waited=0
    backoff=2
    acquired=false
    while [ $waited -lt 120 ]; do
        sleep $backoff
        waited=$((waited + backoff))
        backoff=$((backoff * 2))
        if flock -n 200; then
            acquired=true
            break
        fi
    done
    if [ "$acquired" = false ]; then
        echo "FAIL"
        exit 2
    fi
fi
echo "OK"

# Ensure lock release on exit
trap 'flock -u 200; rm -f "$LOCK_FILE"' EXIT

started_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname_val=$(hostname)
plan_hash=$(sha256sum "$PLAN_FILE" | awk '{print $1}')

# Universal jq expression to extract entries whether PLAN_FILE is a root array or an object with entries/packages
JQ_FILTER='if type=="array" then . else (.entries // .packages // .plan // []) end'

entry_count=$(jq "($JQ_FILTER) | length" "$PLAN_FILE" 2>/dev/null || echo 0)
echo "[*] Loading plan: $PLAN_FILE ($entry_count entries)"

entries_json="[]"
succeeded_count=0
failed_count=0
overall_success=true

index=0
while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    index=$((index + 1))
    
    pkg=$(echo "$entry" | jq -r '.package // .name // empty')
    urgency=$(echo "$entry" | jq -r '.urgency // "scheduled"')
    requires_restart=$(echo "$entry" | jq -r '.requires_restart // false')
    
    linked_services=$(echo "$entry" | jq -r '.linked_services[]? // empty' 2>/dev/null || true)

    # Pre-block capture
    pre_version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "not-installed")
    pre_services="{}"
    for svc in $linked_services; do
        [ -z "$svc" ] && continue
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        pre_services=$(echo "$pre_services" | jq --arg s "$svc" --arg st "$st" '. + {($s): $st}')
    done

    # Run apt upgrade with exponential backoff for dpkg locks
    start_time_sec=$(date +%s.%N)
    export DEBIAN_FRONTEND=noninteractive
    
    apt_output=""
    apt_status=0
    apt_waited=0
    apt_backoff=2

    while true; do
        apt_output=$(apt-get install --only-upgrade -y "$pkg" 2>&1)
        apt_status=$?
        if [ $apt_status -ne 0 ] && echo "$apt_output" | grep -q "Could not get lock"; then
            if [ $apt_waited -lt 120 ]; then
                sleep $apt_backoff
                apt_waited=$((apt_waited + apt_backoff))
                apt_backoff=$((apt_backoff * 2))
                continue
            fi
        fi
        break
    done

    end_time_sec=$(date +%s.%N)
    duration=$(echo "$end_time_sec - $start_time_sec" | bc 2>/dev/null || echo "2.0")

    # Post-block capture
    post_version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "not-installed")
    post_services="{}"
    
    for svc in $linked_services; do
        [ -z "$svc" ] && continue
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        post_services=$(echo "$post_services" | jq --arg s "$svc" --arg st "$st" '. + {($s): $st}')

        if [ "$requires_restart" = "true" ] && [ "$apt_status" -eq 0 ]; then
            if systemctl try-restart "$svc" >/dev/null 2>&1; then
                echo "      try-restart $svc         OK"
            else
                echo "      try-restart $svc         FAIL"
            fi
        fi
    done

    status="OK"
    if [ "$apt_status" -ne 0 ]; then
        status="FAILED"
        overall_success=false
        failed_count=$((failed_count + 1))
    else
        succeeded_count=$((succeeded_count + 1))
    fi

    dur_fmt=$(printf "%.1f" "$duration")
    printf "[%d/%d] %-22s %-10s apt-get ... %s (%ss)\n" "$index" "$entry_count" "$pkg" "$urgency" "$status" "$dur_fmt"

    stdout_tail=$(echo "$apt_output" | tail -n 5)
    stderr_tail=""
    if [ "$apt_status" -ne 0 ]; then
        stderr_tail="$stdout_tail"
    fi

    entries_json=$(echo "$entries_json" | jq \
        --arg p "$pkg" \
        --arg st "$status" \
        --argjson dur "$dur_fmt" \
        --arg pv "$pre_version" \
        --arg pov "$post_version" \
        --arg sout "$stdout_tail" \
        --arg serr "$stderr_tail" \
        --argjson pres "$pre_services" \
        --argjson posts "$post_services" \
        '. + [{
            package: $p,
            status: $st,
            duration_seconds: $dur,
            pre: {version: $pv, services: $pres},
            post: {version: $pov, services: $posts},
            stdout_tail: $sout,
            stderr_tail: $serr
        }]')

    if [ "$apt_status" -ne 0 ]; then
        break
    fi

done < <(jq -c "($JQ_FILTER)[]" "$PLAN_FILE")

finished_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Succeeded: $succeeded_count  Failed: $failed_count"
echo -n "Log saved to: $LOG_FILE"

jq -n \
    --arg sa "$started_at" \
    --arg fa "$finished_at" \
    --arg hn "$hostname_val" \
    --arg ph "$plan_hash" \
    --argjson ent "$entries_json" \
    '{
        started_at: $sa,
        finished_at: $fa,
        hostname: $hn,
        plan_source_hash: $ph,
        entries: $ent
    }' > "$LOG_FILE"

if [ "$overall_success" = true ]; then
    exit 0
else
    exit 1
fi
