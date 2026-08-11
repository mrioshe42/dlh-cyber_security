#!/bin/bash
# name: 7-apt_recovery.sh
# purpose: Diagnose and repair a broken apt/dpkg state from interrupted upgrades.

set -uo pipefail

START_TIME=$(date +%s)
REPORT_FILE="apt_recovery.json"
SERVICE_MAP="service_dependency_map.json"

echo "[*] Diagnosing..."

# Check for live dpkg/apt processes
live_procs=$(pgrep -fa "dpkg|apt" || true)
if [ -n "$live_procs" ]; then
    echo "    live dpkg/apt processes: detected"
    echo "$live_procs" >&2
    exit 2
else
    echo "    live dpkg/apt processes: none"
fi

# Inspect locks
stale_locks=""
for lockfile in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
    if [ -f "$lockfile" ]; then
        stale_locks="${stale_locks:+$stale_locks, }$lockfile"
    fi
done
echo "    stale locks: ${stale_locks:-none}"

# Proper dpkg --audit parsing and actual broken/unconfigured count
audit_raw=$(dpkg --audit 2>/dev/null || true)
# Extract package names correctly from dpkg --audit (column 1 usually contains the package name)
audit_pkgs=$(echo "$audit_raw" | awk '{print $1}' | grep -v '^$' | sort -u || true)

# Also look for true broken packages from dpkg -l (unpacked, half-configured, half-installed, triggers-pending)
dpkg_broken=$(dpkg -l | awk '/^[hi]U|[hi]F|[hi]H|[hi]W|[hi]T|^.([FUnhiRHz])([[:space:]])/ {print $2}' || true)
if [ -f /var/lib/dpkg/status ]; then
    status_broken=$(grep -B 2 -A 5 -E "Status: install ok (half-configured|unpacked|half-installed|triggers-awaited|triggers-pending)" /var/lib/dpkg/status 2>/dev/null | grep "^Package:" | awk '{print $2}' || true)
    dpkg_broken=$(echo -e "$dpkg_broken\n$status_broken" | grep -v '^$' | sort -u)
fi

# Combine and filter unique actual broken packages
broken_pkgs_list=$(echo -e "$audit_pkgs\n$dpkg_broken" | grep -v '^$' | sort -u)
broken_count=$(echo "$broken_pkgs_list" | grep -v '^$' | wc -l || echo 0)

# Format single-line summary for display like the expected output
audit_summary=$(echo "$audit_pkgs" | tr '\n' ', ' | sed 's/,$//')
if [ -z "$audit_summary" ]; then
    audit_summary=$(echo "$broken_pkgs_list" | tr '\n' ', ' | sed 's/,$//')
fi

echo "    dpkg --audit: ${audit_summary:-none}"
echo "    broken packages: $broken_count"

# Check free space on / and /var
root_space=$(df / | awk 'NR==2 {print $4}')
var_space=$(df /var 2>/dev/null | awk 'NR==2 {print $4}' || echo "$root_space")

actions_json="[]"
add_action() {
    local action_name="$1"
    local status="$2"
    actions_json=$(echo "$actions_json" | jq --arg n "$action_name" --arg s "$status" '. + [{action: $n, status: $s}]')
}

echo "[*] Repairing..."

# Execution steps in strict order
if [ -n "$stale_locks" ]; then
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    echo "    remove stale locks                     OK"
    add_action "remove stale locks" "OK"
else
    echo "    remove stale locks                     SKIPPED (none)"
    add_action "remove stale locks" "SKIPPED"
fi

if dpkg --configure -a; then
    echo "    dpkg --configure -a                    OK"
    add_action "dpkg --configure -a" "OK"
else
    echo "    dpkg --configure -a                    FAIL"
    add_action "dpkg --configure -a" "FAIL"
fi

export DEBIAN_FRONTEND=noninteractive
if apt-get --fix-broken install -y; then
    echo "    apt-get --fix-broken install           OK"
    add_action "apt-get --fix-broken install" "OK"
else
    echo "    apt-get --fix-broken install           FAIL"
    add_action "apt-get --fix-broken install" "FAIL"
fi

# Re-run audit checks
final_audit_raw=$(dpkg --audit 2>/dev/null || true)
final_audit_pkgs=$(echo "$final_audit_raw" | awk '{print $1}' | grep -v '^$' || true)
remaining_broken=$(dpkg -l | awk '/^[hi]U|[hi]F|[hi]H|[hi]W|[hi]T/ {print $2}' || true)
if [ -f /var/lib/dpkg/status ]; then
    remaining_status_pkgs=$(grep -B 2 -A 5 -E "Status: install ok (half-configured|unpacked|half-installed|triggers-awaited|triggers-pending)" /var/lib/dpkg/status 2>/dev/null | grep "^Package:" | awk '{print $2}' || true)
    remaining_broken=$(echo -e "$remaining_broken\n$remaining_status_pkgs" | grep -v '^$' | sort -u)
fi

if [ -z "$final_audit_pkgs" ] && [ -z "$remaining_broken" ]; then
    echo "    dpkg --audit (re-run)                  clean"
    audit_status="clean"
else
    echo "    dpkg --audit (re-run)                  issues remaining"
    audit_status="dirty"
fi

echo "[*] Restarting affected services..."
restarted_services=()
if [ -f "$SERVICE_MAP" ]; then
    while IFS="=" read -r pkg service; do
        if echo "$broken_pkgs_list" | grep -qx "$pkg"; then
            systemctl restart "$service" 2>/dev/null || true
            status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
            echo "    $service                        $status"
            restarted_services+=("$service")
        fi
    done < <(jq -r 'to_entries[] | "\(.key)=\(.value)"' "$SERVICE_MAP" 2>/dev/null || true)
fi

if [ ${#restarted_services[@]} -eq 0 ]; then
    for svc in apache2 mysql nginx postgresql; do
        if systemctl is-enabled "$svc.service" >/dev/null 2>&1 || systemctl list-unit-files --full --all 2>/dev/null | grep -q "^$svc.service"; then
            systemctl restart "$svc" 2>/dev/null || true
            status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            echo "    $svc.service                        $status"
        fi
    done
fi

END_TIME=$(date +%s)
duration=$((END_TIME - START_TIME))

recovered=false
exit_code=1
if [ "$audit_status" == "clean" ]; then
    recovered=true
    exit_code=0
    echo -n "RECOVERED: yes"
else
    echo -n "RECOVERED: no"
fi

echo "Duration: ${duration}s"
echo "Report saved to: $REPORT_FILE"

jq -n \
    --arg diag "${audit_summary:-none}" \
    --argjson actions "$actions_json" \
    --arg fstate "$audit_status" \
    --argjson rec "$recovered" \
    --argjson dur "$duration" \
    '{
        initial_diagnosis: $diag,
        actions_taken: $actions,
        final_state: $fstate,
        recovered: $rec,
        duration_seconds: $dur
    }' > "$REPORT_FILE"

exit $exit_code
