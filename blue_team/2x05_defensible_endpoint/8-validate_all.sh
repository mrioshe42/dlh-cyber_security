#!/bin/bash
# Script Name: 8-validate_all.sh
# Description: Universal validation dispatcher that reads target_state.json,
#              evaluates all controls, outputs a control family summary table,
#              and exits with code 0 only if all checks pass.
# Exit Codes:  0 = All controls passed (fail_count == 0 && error_count == 0)
#              1 = One or more controls failed or encountered an error
#              2 = Environment/Prerequisite Error (missing target_state.json, jq)

set -uo pipefail
# target_state.controls grep -E
TARGET_STATE_PATH="capstone/target_state.json"
REPORT_PATH="capstone/validation_report.json"

if [ ! -f "$TARGET_STATE_PATH" ]; then
    echo "[-] Error: Target state file not found at $TARGET_STATE_PATH" >&2
    exit 2
fi

if ! command -v jq &>/dev/null; then
    echo "[-] Error: 'jq' is required but not installed." >&2
    exit 2
fi

echo "[+] Initializing End-to-End Validation Suite using $TARGET_STATE_PATH..."

TOTAL_CONTROLS=0
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

RESULTS_TMP=$(mktemp)
trap 'rm -f "$RESULTS_TMP"' EXIT

CONTROL_COUNT=$(jq '.controls | length' "$TARGET_STATE_PATH")

if [ "$CONTROL_COUNT" -eq 0 ]; then
    echo "[-] Error: No controls defined in target_state.json" >&2
    exit 2
fi

# Iterate Over Controls
for ((i=0; i<CONTROL_COUNT; i++)); do
    TOTAL_CONTROLS=$((TOTAL_CONTROLS + 1))
    
    CTRL_ID=$(jq -r ".controls[$i].id // \"UNKNOWN\"" "$TARGET_STATE_PATH")
    CTRL_FAMILY=$(jq -r ".controls[$i].family // \"GENERAL\"" "$TARGET_STATE_PATH")
    CHECK_TYPE=$(jq -r ".controls[$i].check_type // \"\"" "$TARGET_STATE_PATH")
    CHECK_TARGET=$(jq -r ".controls[$i].check_target // \"\"" "$TARGET_STATE_PATH")
    EXPECTED_VAL=$(jq -r ".controls[$i].expected_value // \"\"" "$TARGET_STATE_PATH")
    JSON_FIELD=$(jq -r ".controls[$i].json_field // \"\"" "$TARGET_STATE_PATH")

    VERDICT="fail"
    EVIDENCE=""

    # Dispatch Check Type
    case "$CHECK_TYPE" in
        file_exists)
            if [ -e "$CHECK_TARGET" ]; then
                VERDICT="pass"
                EVIDENCE="File exists: $CHECK_TARGET"
            else
                EVIDENCE="File missing: $CHECK_TARGET"
            fi
            ;;

        json_field_equals)
            if [ -f "$CHECK_TARGET" ]; then
                VAL=$(jq -r ".$JSON_FIELD // empty" "$CHECK_TARGET" 2>/dev/null || echo "")
                if [ "$VAL" = "$EXPECTED_VAL" ]; then
                    VERDICT="pass"
                    EVIDENCE="JSON field .$JSON_FIELD equals '$VAL'"
                else
                    EVIDENCE="JSON field mismatch: got '$VAL', expected '$EXPECTED_VAL'"
                fi
            else
                VERDICT="error"
                EVIDENCE="Target JSON file not found: $CHECK_TARGET"
            fi
            ;;

        json_field_gte)
            if [ -f "$CHECK_TARGET" ]; then
                VAL=$(jq -r ".$JSON_FIELD // -1" "$CHECK_TARGET" 2>/dev/null || echo "-1")
                if awk "BEGIN {exit !($VAL >= $EXPECTED_VAL)}"; then
                    VERDICT="pass"
                    EVIDENCE="JSON field .$JSON_FIELD value $VAL >= $EXPECTED_VAL"
                else
                    EVIDENCE="JSON field value $VAL is less than expected $EXPECTED_VAL"
                fi
            else
                VERDICT="error"
                EVIDENCE="Target JSON file not found: $CHECK_TARGET"
            fi
            ;;

        command_exit_zero)
            if eval "$CHECK_TARGET" &>/dev/null; then
                VERDICT="pass"
                EVIDENCE="Command exited 0: $CHECK_TARGET"
            else
                EVIDENCE="Command failed or non-zero exit: $CHECK_TARGET"
            fi
            ;;

        grep_match)
            if [ -f "$CHECK_TARGET" ]; then
                if grep -q -E "$EXPECTED_VAL" "$CHECK_TARGET" 2>/dev/null; then
                    VERDICT="pass"
                    EVIDENCE="Pattern '$EXPECTED_VAL' matched in $CHECK_TARGET"
                else
                    EVIDENCE="Pattern '$EXPECTED_VAL' not found in $CHECK_TARGET"
                fi
            else
                VERDICT="error"
                EVIDENCE="Target file for grep not found: $CHECK_TARGET"
            fi
            ;;

        *)
            VERDICT="error"
            EVIDENCE="Unknown check_type: $CHECK_TYPE"
            ;;
    esac

    # Tally results
    case "$VERDICT" in
        pass) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        fail) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        error) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac

    echo "$CTRL_FAMILY|$CTRL_ID|$VERDICT|$EVIDENCE" >> "$RESULTS_TMP"
done

# Calculate Pass Percentage
if [ "$TOTAL_CONTROLS" -gt 0 ]; then
    PASS_PERCENT=$(awk "BEGIN {printf \"%.2f\", ($PASS_COUNT / $TOTAL_CONTROLS) * 100}")
else
    PASS_PERCENT="0.00"
fi

mkdir -p capstone
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson total "$TOTAL_CONTROLS" \
    --argjson pass "$PASS_COUNT" \
    --argjson fail "$FAIL_COUNT" \
    --argjson error "$ERROR_COUNT" \
    --arg pass_pct "$PASS_PERCENT" \
    '{
        timestamp: $timestamp,
        summary: {
            total_controls: $total,
            passed: $pass,
            failed: $fail,
            errors: $error,
            pass_percentage: ($pass_pct | tonumber)
        }
    }' > "$REPORT_PATH"

echo ""
echo "                   MEDDEFENSE END-TO-END VALIDATION REPORT                    "
printf "%-25s | %-8s | %-8s | %-8s | %-10s\n" "CONTROL FAMILY" "TOTAL" "PASS" "FAIL/ERR" "STATUS"
echo "------------------------------------------------------------------------------"

awk -F'|' '{
    family=$1; verdict=$3;
    total[family]++;
    if(verdict=="pass") pass[family]++;
    else if(verdict=="fail" || verdict=="error") fail[family]++;
} END {
    for (f in total) {
        t = total[f];
        p = (pass[f] ? pass[f] : 0);
        fe = (fail[f] ? fail[f] : 0);
        status = (fe == 0) ? "PASS" : "FAIL";
        printf "%-25s | %-8d | %-8d | %-8d | %-10s\n", f, t, p, fe, status;
    }
}' "$RESULTS_TMP"

echo "=============================================================================="
printf "Overall Summary: %d/%d Passed (%s%%) | Fails: %d | Errors: %d\n" \
    "$PASS_COUNT" "$TOTAL_CONTROLS" "$PASS_PERCENT" "$FAIL_COUNT" "$ERROR_COUNT"
echo "Detailed report persisted to: $REPORT_PATH"
echo "=============================================================================="

if [ "$FAIL_COUNT" -eq 0 ] && [ "$ERROR_COUNT" -eq 0 ]; then
    echo "[+] Verdict: Environment is READY for handoff."
    exit 0
else
    echo "[-] Verdict: Environment is NOT ready. Resolve failing controls and re-run." >&2
    exit 1
fi
