#!/bin/bash

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
RULES_DIR="rules/sigma"
OUT_FILE="fp_baseline.json"

mkdir -p "$CATALOG_DIR"

SUMMARY_FILE="$BASELINE_PKG/baselines/baseline_summary.json"
WINDOW_START="2026-03-18T00:00:00Z"
WINDOW_END="2026-03-24T23:59:59Z"

if [ -f "$SUMMARY_FILE" ]; then
    WS=$(jq -r '.window_start // .start_date // .baseline_start // empty' "$SUMMARY_FILE" 2>/dev/null || true)
    WE=$(jq -r '.window_end // .end_date // .baseline_end // empty' "$SUMMARY_FILE" 2>/dev/null || true)
    [ -n "$WS" ] && WINDOW_START="$WS"
    [ -n "$WE" ] && WINDOW_END="$WE"
fi

if [ -d "$RULES_DIR" ]; then
    shopt -s nullglob
    rules=( "$RULES_DIR"/*.yml )
else
    rules=()
fi

num_rules=${#rules[@]}

echo "evaluating $num_rules rules against baseline window $WINDOW_START -> $WINDOW_END"

results=()
for rule in "${rules[@]}"; do
    [ -e "$rule" ] || continue
    
    runner_out=$(./3-sigma_runner.sh "$rule" --window "$WINDOW_START,$WINDOW_END")
    
    rule_id=$(echo "$runner_out" | jq -r '.rule_id // "unknown-id"')
    rule_title=$(echo "$runner_out" | jq -r '.rule_title // "unknown-title"')
    level=$(echo "$runner_out" | jq -r '.level // "medium"')
    fp_count=$(echo "$runner_out" | jq -r '.match_count // 0')
    
    fp_rate=$(python3 -c "print(round(float($fp_count) / 7.0, 2))")
    
    filename=$(basename "$rule" .yml)
    
    tune_tag=""
    if [ "$fp_count" -gt 10 ]; then
        tune_tag="   [TUNE]"
    fi
    
    printf "  %-30s fp=%3d%s\n" "$filename" "$fp_count" "$tune_tag"
    
    json_item=$(jq -n \
        --arg rid "$rule_id" \
        --arg rtitle "$rule_title" \
        --arg lvl "$level" \
        --argjson fpc "$fp_count" \
        --arg ws "$WINDOW_START" \
        --arg we "$WINDOW_END" \
        --argjson fpr "$fp_rate" \
        '{rule_id: $rid, rule_title: $rtitle, level: $lvl, fp_count: $fpc, baseline_window_start: $ws, baseline_window_end: $we, fp_rate_per_day: $fpr}')
    results+=("$json_item")
done

if [ ${#results[@]} -gt 0 ]; then
    printf '%s\n' "${results[@]}" | jq -s '.' > "$OUT_FILE"
else
    echo "[]" > "$OUT_FILE"
fi

echo "fp_baseline.json written"
