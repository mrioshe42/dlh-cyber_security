#!/bin/bash
# name: 15-handoff_validation.sh
# purpose: Validate the telemetry handoff package against quality gates to ensure Minimum Event Counts readiness for analyst consumption.
# author: Massimo Rios

set -e
set -u
set -o pipefail

WIN_EVENTS="telemetry_handoff/windows_events.json"
LIN_EVENTS="telemetry_handoff/linux_events.json"
GROUND_TRUTH="telemetry_handoff/attack_ground_truth.json"
WIN_DM="windows_detection_matrix.json"
LIN_DM="linux_detection_matrix.json"
VALIDATION_OUT="handoff_validation.json"

for cmd in jq date du awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required command not found: $cmd" >&2
        exit 1
    fi
done

TOTAL_CHECKS=14
PASSED_CHECKS=0
VALIDATION_LOGS=()

add_result() { # category, status(PASS/FAIL), message
    local cat="$1"
    local status="$2"
    local msg="$3"
    VALIDATION_LOGS+=("$(jq -n --arg c "$cat" --arg s "$status" --arg m "$msg" '{category: $c, status: $s, message: $m}')")
    if [ "$status" = "PASS" ]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        echo "[PASS] $msg"
    else
        echo "[FAIL] $msg" >&2
    fi
}

human_size() {
    local file="$1"
    local b
    b=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
    awk -v bytes="$b" 'BEGIN {
        if (bytes >= 1048576) printf "%.1f MB", bytes / 1048576;
        else if (bytes >= 1024) printf "%d KB", bytes / 1024;
        else printf "%d B", bytes;
    }'
}

commafy() {
    echo "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

json_count() {
    local file="$1"
    if [ -f "$file" ]; then
        jq 'if type == "array" then length else (.events // .actions // .windows_actions // []) | length end' "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

echo "[*] Validating telemetry_handoff/ ..."

if [ -f "telemetry_handoff/windows_events.json" ]; then
    add_result "file_existence" "PASS" "windows_events.json exists ($(human_size "telemetry_handoff/windows_events.json"))"
else
    add_result "file_existence" "FAIL" "windows_events.json exists"
fi

if [ -f "telemetry_handoff/linux_events.json" ]; then
    add_result "file_existence" "PASS" "linux_events.json exists ($(human_size "telemetry_handoff/linux_events.json"))"
else
    add_result "file_existence" "FAIL" "linux_events.json exists"
fi

if [ -f "telemetry_handoff/attack_ground_truth.json" ]; then
    add_result "file_existence" "PASS" "attack_ground_truth.json exists ($(human_size "telemetry_handoff/attack_ground_truth.json"))"
else
    add_result "file_existence" "FAIL" "attack_ground_truth.json exists"
fi

if [ -f "telemetry_handoff/windows_events.json" ] && jq empty "telemetry_handoff/windows_events.json" >/dev/null 2>&1; then
    WIN_COUNT=$(json_count "telemetry_handoff/windows_events.json")
    add_result "json_validity" "PASS" "windows_events.json: valid JSON, $WIN_COUNT objects"
else
    add_result "json_validity" "FAIL" "windows_events.json: valid JSON"
    WIN_COUNT=0
fi

if [ -f "telemetry_handoff/linux_events.json" ] && jq empty "telemetry_handoff/linux_events.json" >/dev/null 2>&1; then
    LIN_COUNT=$(json_count "telemetry_handoff/linux_events.json")
    add_result "json_validity" "PASS" "linux_events.json: valid JSON, $LIN_COUNT objects"
else
    add_result "json_validity" "FAIL" "linux_events.json: valid JSON"
    LIN_COUNT=0
fi

if [ -f "telemetry_handoff/attack_ground_truth.json" ] && jq empty "telemetry_handoff/attack_ground_truth.json" >/dev/null 2>&1; then
    GT_COUNT=$(json_count "telemetry_handoff/attack_ground_truth.json")
    add_result "json_validity" "PASS" "attack_ground_truth.json: valid JSON, $GT_COUNT objects"
else
    add_result "json_validity" "FAIL" "attack_ground_truth.json: valid JSON"
    GT_COUNT=0
fi

MISSING_FIELDS=$(jq -n \
    --slurpfile w "telemetry_handoff/windows_events.json" \
    --slurpfile l "telemetry_handoff/linux_events.json" '
    def arr($x): ($x[0] | if type == "array" then . elif type == "object" then (.events // []) else [] end);
    (arr($w) + arr($l)) as $ev
    | [
        $ev[] |
        select(
            (.timestamp == null or .hostname == null or .source_type == null or .event_category == null)
        )
      ] | length
' 2>/dev/null || echo -1)

if [ "$MISSING_FIELDS" = "0" ]; then
    add_result "required_fields" "PASS" "All events have timestamp, hostname, source_type, event_category"
else
    add_result "required_fields" "FAIL" "$MISSING_FIELDS event(s) missing required fields"
fi

if [ "$WIN_COUNT" -ge 1000 ]; then
    add_result "min_counts" "PASS" "Windows: $(commafy "$WIN_COUNT") >= 1,000"
else
    add_result "min_counts" "FAIL" "Windows: $WIN_COUNT >= 1,000"
fi

if [ "$LIN_COUNT" -ge 500 ]; then
    add_result "min_counts" "PASS" "Linux: $(commafy "$LIN_COUNT") >= 500"
else
    add_result "min_counts" "FAIL" "Linux: $LIN_COUNT >= 500"
fi

if [ "$GT_COUNT" -ge 10 ]; then
    add_result "min_counts" "PASS" "Ground truth: $GT_COUNT >= 10"
else
    add_result "min_counts" "FAIL" "Ground truth: $GT_COUNT >= 10"
fi

NOW=$(date -u +%s)
TS_INFO=$(jq -n \
    --slurpfile w "telemetry_handoff/windows_events.json" \
    --slurpfile l "telemetry_handoff/linux_events.json" \
    --argjson now "$NOW" '
    def arr($x): ($x[0] | if type == "array" then . elif type == "object" then (.events // []) else [] end);
    def isoRE: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$";
    def norm: sub("[+]00:00$";"Z") | sub("[.][0-9]+";"");
    def ep: (norm | try fromdateiso8601 catch null);
    arr($w) as $wv | arr($l) as $lv
    | ([ $wv[].timestamp // "" | tostring ]) as $wts
    | ([ $lv[].timestamp // "" | tostring ]) as $lts
    | ($wts + $lts) as $all
    | ([ $all[] | ep | select(. != null) ]) as $alle
    | ([ $wts[] | ep | select(. != null) ]) as $we
    | ([ $lts[] | ep | select(. != null) ]) as $le
    | {
        total: ($all | length),
        invalid: ([ $all[] | select((test(isoRE)) | not) ] | length),
        future: ([ $alle[] | select(. > $now) ] | length),
        min: ($alle | min), max: ($alle | max),
        wmin: ($we | min), wmax: ($we | max),
        lmin: ($le | min), lmax: ($le | max)
    }
' 2>/dev/null || echo '{}')

INVALID_TS=$(jq -r '.invalid // -1' <<<"$TS_INFO")
FUTURE_TS=$(jq -r '.future // -1' <<<"$TS_INFO")
MIN_EP=$(jq -r '.min // empty' <<<"$TS_INFO")
MAX_EP=$(jq -r '.max // empty' <<<"$TS_INFO")
W_MIN=$(jq -r '.wmin // empty' <<<"$TS_INFO")
W_MAX=$(jq -r '.wmax // empty' <<<"$TS_INFO")
L_MIN=$(jq -r '.lmin // empty' <<<"$TS_INFO")
L_MAX=$(jq -r '.lmax // empty' <<<"$TS_INFO")

if [ "$INVALID_TS" = "0" ]; then
    add_result "timestamps" "PASS" "All timestamps valid ISO 8601"
else
    add_result "timestamps" "FAIL" "$INVALID_TS timestamp(s) not valid ISO 8601"
fi

if [ "$FUTURE_TS" = "0" ]; then
    add_result "timestamps" "PASS" "No future timestamps"
else
    add_result "timestamps" "FAIL" "$FUTURE_TS future timestamp(s) detected"
fi

if [ -n "$MIN_EP" ] && [ -n "$MAX_EP" ]; then
    R_MIN=$(date -u -d "@$MIN_EP" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$MIN_EP" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "2026-03-25T00:00:00Z")
    R_MAX=$(date -u -d "@$MAX_EP" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$MAX_EP" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "2026-03-25T23:59:59Z")
    echo "[PASS] Range: $R_MIN to $R_MAX"
else
    R_MIN=""
    R_MAX=""
    echo "[INFO] Range: unavailable"
fi

read -r OV_OK OV_HOURS < <(awk -v a="$W_MIN" -v b="$W_MAX" -v c="$L_MIN" -v d="$L_MAX" 'BEGIN {
    if (a=="" || b=="" || c=="" || d=="") { print "0 0"; exit }
    lo=(a>c?a:c); hi=(b<d?b:d); ov=hi-lo;
    if (ov>0) printf "1 %.1f", ov/3600; else print "0 0";
}')

if [ "$OV_OK" = "1" ]; then
    add_result "alignment" "PASS" "Windows and Linux time ranges overlap (${OV_HOURS} hours shared)"
else
    add_result "alignment" "FAIL" "Windows and Linux time ranges do not overlap"
fi

GT_CHECK=$(jq -n \
    --slurpfile gt "telemetry_handoff/attack_ground_truth.json" \
    --slurpfile wdm "windows_detection_matrix.json" \
    --slurpfile ldm "linux_detection_matrix.json" '
     (($gt[0].actions // $gt[0].windows_actions // [])) as $A
    | ([ (($wdm[0].matrix // $wdm[0].actions // []))[] | {p: "windows", n: (.action_number // .id)} ]
      + [ (($ldm[0].matrix // $ldm[0].actions // []))[] | {p: "linux", n: (.action_number // .id)} ]) as $M
    | {
        matched: ([ $A[] | . as $a | select(any($M[]; .p == ($a.platform // "windows") and .n == ($a.action_number // $a.id))) ] | length),
        total: ($A | length)
      }
' 2>/dev/null || echo '{"matched":0,"total":0}')

MATCHED=$(jq -r '.matched // 0' <<<"$GT_CHECK")
GT_TOTAL=$(jq -r '.total // 0' <<<"$GT_CHECK")
# Ground Truth Completeness
if [ "$GT_TOTAL" -gt 0 ] && [ "$MATCHED" = "$GT_TOTAL" ]; then
    add_result "ground_truth" "PASS" "$MATCHED/$GT_TOTAL actions have detection matrix entries"
else
    add_result "ground_truth" "FAIL" "$MATCHED/$GT_TOTAL actions have detection matrix entries"
fi

VERDICT="FAIL"
if [ "$PASSED_CHECKS" -eq "$TOTAL_CHECKS" ]; then
    VERDICT="PASS"
    echo "VERDICT: PASS ($PASSED_CHECKS/$TOTAL_CHECKS checks)"
    echo "Handoff package is ready for Module 3."
else
    echo "VERDICT: FAIL ($PASSED_CHECKS/$TOTAL_CHECKS checks passed)" >&2
fi

LOGS_JSON=$(printf '%s\n' "${VALIDATION_LOGS[@]}" | jq -s '.')
jq -n \
    --arg verdict "$VERDICT" \
    --argjson passed "$PASSED_CHECKS" \
    --argjson total "$TOTAL_CHECKS" \
    --arg range_min "${R_MIN:-}" \
    --arg range_max "${R_MAX:-}" \
    --arg overlap_hours "${OV_HOURS:-0}" \
    --argjson results "$LOGS_JSON" \
    '{
        generated_at: (now | todateiso8601),
        verdict: $verdict,
        checks_passed: $passed,
        checks_total: $total,
        timestamp_range: { min: $range_min, max: $range_max },
        cross_platform_overlap_hours: ($overlap_hours | tonumber),
        results: $results
    }' > "$VALIDATION_OUT"

echo "Report saved to: $VALIDATION_OUT"

