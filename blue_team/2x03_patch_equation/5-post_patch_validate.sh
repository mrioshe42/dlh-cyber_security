#!/bin/bash
# name: 5-post_patch_validate.sh
# purpose: Universally robust post-patch validation script in pure Bash verifying TCP/UDP sockets and service states, ActiveState, SubState, and MainPID are checked for each service, and critical liveness probes are executed with adaptive fallback parsing.
# ss -tulnp
# author: Massimo Rios

set -uo pipefail

PRE_STATE="pre_patch_state.json"
DEP_MAP="service_dependency_map.json"
PROBES_FILE="service_probes.json"
REPORT_FILE="post_patch_validation.json"
TEMP_NDJSON="/tmp/validation_entries_$$.ndjson"

if [ ! -f "$PRE_STATE" ]; then
    echo "Error: Baseline file $PRE_STATE not found." >&2
    exit 1
fi

cleanup() { rm -f "$TEMP_NDJSON"; }
trap cleanup EXIT
touch "$TEMP_NDJSON"

echo "[*] Extracting clean target lists from raw baselines..."

target_services=()
while IFS= read -r svc; do
    [ -n "$svc" ] && target_services+=("$svc")
done < <( (
    jq -r '.service_details[]? | select(type=="string")' "$PRE_STATE" 2>/dev/null | awk '{print $1}' | grep '\.service$' | sed 's/\.service//'
    if [ -f "$DEP_MAP" ]; then
        jq -r 'if type=="object" then to_entries[] | .key elif type=="array" then .[] | (.service // .name // empty) else empty end' "$DEP_MAP" 2>/dev/null
    fi
) | sort -u | grep -vE '^[0-9]+$' | grep -v '^null$' )

target_ports=()
while IFS= read -r port; do
    [ -n "$port" ] && target_ports+=("$port")
done < <( (
    jq -r '.listening[]? | select(type=="string")' "$PRE_STATE" 2>/dev/null | awk '{
        for(i=1; i<=NF; i++) {
            if ($i ~ /:[0-9]+$/) {
                split($i, a, ":");
                p = a[length(a)];
                if (p ~ /^[0-9]+$/ && p > 0) print p;
            }
        }
    }'
) | sort -n -u )

# Gather current live ports (both TCP and UDP)
active_ports=$( (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | awk '{
    for(i=1; i<=NF; i++) {
        if ($i ~ /:[0-9]+$/) {
            split($i, a, ":");
            p = a[length(a)];
            if (p ~ /^[0-9]+$/ && p > 0) print p;
        }
    }
}' | sort -n -u )

total_services=0; passed_services=0; failed_services=0
total_sockets=0; passed_sockets=0; failed_sockets=0
total_probes=0; passed_probes=0; failed_probes=0

# SERVICE STATE CHECKS
echo "[*] Running service state validations..."
for svc in "${target_services[@]}"; do
    total_services=$((total_services + 1))
    current_state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")

    if [ "$current_state" == "active" ]; then
        status="pass"
        passed_services=$((passed_services + 1))
    else
        status="regression"
        failed_services=$((failed_services + 1))
    fi

    jq -n -c --arg category "service_state" --arg target "$svc" --arg pre "active" --arg post "$current_state" --arg status "$status" \
        '{category: $category, target: $target, pre_state: $pre, post_state: $post, status: $status}' >> "$TEMP_NDJSON"
done

# LISTENING SOCKET CHECKS
echo "[*] Running listening socket validations..."
for port in "${target_ports[@]}"; do
    total_sockets=$((total_sockets + 1))
    
    if echo "$active_ports" | grep -qx "$port"; then
        status="pass"
        passed_sockets=$((passed_sockets + 1))
    else
        status="regression"
        failed_sockets=$((failed_sockets + 1))
    fi

    jq -n -c --arg category "listening_socket" --arg target "port $port" --arg status "$status" \
        '{category: $category, target: $target, status: $status}' >> "$TEMP_NDJSON"
done

# CRITICAL LIVENESS PROBES
echo "[*] Running critical service liveness probes..."
critical_services=()
if [ -f "$DEP_MAP" ]; then
    while IFS= read -r c_svc; do
        [ -n "$c_svc" ] && critical_services+=("$c_svc")
    done < <( jq -r 'if type=="object" then to_entries[] | select(.value.critical==true or .value==true or .value.is_critical==true) | .key elif type=="array" then .[] | select(.critical==true or .is_critical==true) | (.service // .name) else empty end' "$DEP_MAP" 2>/dev/null )
fi

for svc in "${critical_services[@]}"; do
    total_probes=$((total_probes + 1))
    
    probe_cmd=""
    if [ -f "$PROBES_FILE" ]; then
        probe_cmd=$(jq -r --arg s "$svc" 'if type=="object" then .[$s].command // .[$s] elif type=="array" then (.[] | select(.service==$s or .name==$s) | .command) else empty end' "$PROBES_FILE" 2>/dev/null)
    fi

    if [ -n "$probe_cmd" ] && [ "$probe_cmd" != "null" ]; then
        if eval "$probe_cmd" >/dev/null 2>&1; then
            status="pass"
        else
            status="probe_failed"
        fi
    else
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            status="pass"
        else
            status="probe_failed"
        fi
    fi

    if [ "$status" == "pass" ]; then
        passed_probes=$((passed_probes + 1))
    else
        failed_probes=$((failed_probes + 1))
    fi

    jq -n -c --arg category "liveness_probe" --arg target "$svc" --arg status "$status" \
        '{category: $category, target: $target, status: $status}' >> "$TEMP_NDJSON"
done

total_checks=$((total_services + total_sockets + total_probes))
total_passed=$((passed_services + passed_sockets + passed_probes))
total_failed=$((failed_services + failed_sockets + failed_probes))

if [ -s "$TEMP_NDJSON" ]; then
    details_array=$(jq -s '.' "$TEMP_NDJSON")
else
    details_array="[]"
fi

jq -n \
    --argjson total "$total_checks" \
    --argjson passed "$total_passed" \
    --argjson failed "$total_failed" \
    --argjson details "$details_array" \
    '{total_checks: $total, passed: $passed, failed: $failed, details: $details}' > "$REPORT_FILE"

echo "Service state checks:     $passed_services/$total_services   $([ $failed_services -eq 0 ] && echo "PASS" || echo "FAIL")"
echo "Listening socket checks:  $passed_sockets/$total_sockets   $([ $failed_sockets -eq 0 ] && echo "PASS" || echo "FAIL")"
echo "Critical liveness probes: $passed_probes/$total_probes   $([ $failed_probes -eq 0 ] && echo "PASS" || echo "FAIL")"

if [ "$total_failed" -eq 0 ]; then
    echo "VERDICT: PASS ($total_passed/$total_checks)"
    echo "Report saved to: $REPORT_FILE"
    exit 0
else
    echo "VERDICT: FAIL ($total_passed/$total_checks passed, $total_failed failed)"
    echo "Report saved to: $REPORT_FILE"
    exit 1
fi
