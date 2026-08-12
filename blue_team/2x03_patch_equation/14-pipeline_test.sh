#!/bin/bash
# Script: 14-pipeline_test.sh
# Purpose: End-to-End Pipeline Test Against a Simulated Advisory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

NORM_PLAN=$(mktemp)
NORM_EXPECTED=$(mktemp)
DIFF_TMP=$(mktemp)

cleanup() {
    if [ -f "cve_feed.json.bak" ]; then
        cp "cve_feed.json.bak" "cve_feed.json" 2>/dev/null || true
        rm -f "cve_feed.json.bak" 2>/dev/null || true
    fi
    rm -f "$NORM_PLAN" "$NORM_EXPECTED" "$DIFF_TMP" 2>/dev/null || true
}
trap cleanup EXIT

printf "[*] Scenario: %s\n" "simulated CVE advisory"

# Backup existing cve_feed.json
if [ -f "cve_feed.json" ]; then
    cp "cve_feed.json" "cve_feed.json.bak"
else
    touch "cve_feed.json.bak"
fi
printf "[*] %-41s OK\n" "Backing up cve_feed.json..."

if [ -f "cve_feed.simulated.json" ]; then
    cp "cve_feed.simulated.json" "cve_feed.json"
fi
printf "[*] %-41s OK\n" "Injecting cve_feed.simulated.json..."

# Locate pipeline runner and execute with PIPELINE_TEST=1
PIPELINE_SCRIPT="./13-patch_pipeline.sh"
if [ ! -f "$PIPELINE_SCRIPT" ] && [ -f "./13pe.sh" ]; then
    PIPELINE_SCRIPT="./13pe.sh"
fi

printf "[*] Running pipeline (PIPELINE_TEST=1)...\n"
export PIPELINE_TEST=1
"$PIPELINE_SCRIPT"

# Validate pipeline execution status and emitted JSON artifacts
STAGES_OK=true
if [ -f "pipeline_run.json" ]; then
    STATUS=$(jq -r '.pipeline_status // empty' pipeline_run.json 2>/dev/null || true)
    if [ "$STATUS" != "ok" ] && [ "$STATUS" != "deferred" ]; then
        STAGES_OK=false
    fi

    ARTIFACT_FILES=$(jq -r '.artifacts // {} | .[]' pipeline_run.json 2>/dev/null || true)
    if [ -z "$ARTIFACT_FILES" ]; then
        STAGES_OK=false
    else
        for art in $ARTIFACT_FILES; do
            if [ ! -s "$art" ] || ! jq . "$art" >/dev/null 2>&1; then
                STAGES_OK=false
                break
            fi
        done
    fi
else
    STAGES_OK=false
fi

normalize_json() {
    local infile="$1"
    if [ -f "$infile" ] && [ -s "$infile" ]; then
        jq -S . "$infile" 2>/dev/null | sed -E \
            -e 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[^"]*"/"<TIMESTAMP>"/g' \
            -e 's/("(timestamp|generated_at|created_at|date)":\s*)"[^"]+"/\1"<TIMESTAMP>"/g' \
            -e 's/("(timestamp|generated_at|created_at|date)":\s*)[0-9]+(\.[0-9]+)?/\1"<TIMESTAMP>"/g'
    else
        echo "{}"
    fi
}

normalize_json "patch_plan.json" > "$NORM_PLAN"
normalize_json "patch_plan.expected.json" > "$NORM_EXPECTED"

diff -u "$NORM_EXPECTED" "$NORM_PLAN" > "$DIFF_TMP" || true

if [ ! -s "$DIFF_TMP" ]; then
    PLAN_MATCHES=true
    DIFF_JSON="[]"
    MATCH_TEXT="match"
else
    PLAN_MATCHES=false
    DIFF_JSON=$(jq -R -s 'split("\n") | if .[-1] == "" then .[:-1] else . end' "$DIFF_TMP")
    MATCH_TEXT="mismatch"
fi

printf "[*] %-41s %s\n" "Comparing patch_plan.json to expected..." "$MATCH_TEXT"

# Restore original cve_feed.json
if [ -f "cve_feed.json.bak" ]; then
    cp "cve_feed.json.bak" "cve_feed.json"
    rm -f "cve_feed.json.bak"
fi
printf "[*] %-41s OK\n" "Restoring cve_feed.json..."

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ "$STAGES_OK" = "true" ] && [ "$PLAN_MATCHES" = "true" ]; then
    VERDICT="pass"
    EXIT_CODE=0
else
    VERDICT="fail"
    EXIT_CODE=1
fi

jq -n \
   --arg scenario "simulated CVE advisory" \
   --arg started_at "$STARTED_AT" \
   --arg finished_at "$FINISHED_AT" \
   --argjson stages_ok "$STAGES_OK" \
   --argjson plan_matches_expected "$PLAN_MATCHES" \
   --argjson diff "$DIFF_JSON" \
   --arg verdict "$VERDICT" \
   '{
       scenario: $scenario,
       started_at: $started_at,
       finished_at: $finished_at,
       stages_ok: $stages_ok,
       plan_matches_expected: $plan_matches_expected,
       diff: $diff,
       verdict: $verdict
   }' > "pipeline_test_results.json"

printf "VERDICT: %s\n" "$VERDICT"
printf "Report saved to: pipeline_test_results.json\n"

exit $EXIT_CODE
