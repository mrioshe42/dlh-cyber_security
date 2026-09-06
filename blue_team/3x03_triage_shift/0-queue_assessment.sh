#!/bin/bash

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
QUEUE_FILE="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA_FILE="$CATALOG_DIR/alerts/alert_queue_schema.json"
OUTPUT_FILE="queue_assessment.json"

if [ ! -f "$QUEUE_FILE" ]; then
    echo "Error: Alert queue not found at $QUEUE_FILE" >&2
    exit 1
fi

if [ ! -f "$SCHEMA_FILE" ]; then
    echo "Error: Schema file not found at $SCHEMA_FILE" >&2
    exit 1
fi

jq -n --slurpfile queue "$QUEUE_FILE" '
{
  queue_size: ($queue[0] | length),
  validation_errors: [
    ($queue[0] | to_entries[] | select(.value.alert_id == null or .value.rule_id == null or .value.priority_score == null) | {index: .key, error: "Missing required fields"})
  ],
  by_priority_band: {
    critical: [ $queue[0][] | select(.priority_score >= 20) ] | length,
    high: [ $queue[0][] | select(.priority_score >= 10 and .priority_score < 20) ] | length,
    medium: [ $queue[0][] | select(.priority_score >= 5 and .priority_score < 10) ] | length,
    low: [ $queue[0][] | select(.priority_score >= 1 and .priority_score < 5) ] | length
  },
  by_rule: [
    ($queue[0] | group_by(.rule_id) | map({key: .[0].rule_id, value: length}) | from_entries)
  ][0],
  by_hostname: [
    ($queue[0] | group_by(.target_host // .hostname // .host // "unknown_host") | map({key: (.[0].target_host // .[0].hostname // .[0].host // "unknown_host"), value: length}) | from_entries)
  ][0],
  by_attack_tactic: [
    ($queue[0] | group_by(.attack_tactic // "unknown") | map({key: (.[0].attack_tactic // "unknown"), value: length}) | from_entries)
  ][0],
  time_span: {
    start: ([ $queue[0][].timestamp // $queue[0][].event_summary.timestamp ] | sort | .[0]),
    end: ([ $queue[0][].timestamp // $queue[0][].event_summary.timestamp ] | sort | .[-1])
  },
  top_targets: [
    ($queue[0] | group_by(.target_host // .hostname // .host // "unknown_host") | map({hostname: (.[0].target_host // .[0].hostname // .[0].host // "unknown_host"), score: map(.priority_score) | add}) | sort_by(.score) | reverse | .[0:3][])
  ]
}' > "$OUTPUT_FILE"

CURRENT_DATE=$(date -u +%Y-%m-%d)
QUEUE_SIZE=$(jq '.queue_size' "$OUTPUT_FILE")
VAL_ERRS=$(jq '.validation_errors | length' "$OUTPUT_FILE")
TIME_START=$(jq -r '.time_span.start' "$OUTPUT_FILE")
TIME_END=$(jq -r '.time_span.end' "$OUTPUT_FILE")
CRIT=$(jq '.by_priority_band.critical' "$OUTPUT_FILE")
HIGH=$(jq '.by_priority_band.high' "$OUTPUT_FILE")
MED=$(jq '.by_priority_band.medium' "$OUTPUT_FILE")
LOW=$(jq '.by_priority_band.low' "$OUTPUT_FILE")
TACTICS_COUNT=$(jq '.by_attack_tactic | keys | length' "$OUTPUT_FILE")

echo "=== SHIFT BRIEFING $CURRENT_DATE ==="
echo "queue size           : $QUEUE_SIZE alerts"
echo "validation errors    :  $VAL_ERRS"
echo "time span            : $TIME_START -> $TIME_END"
echo "priority bands"
echo "  critical  :  $CRIT"
echo "  high      : $HIGH"
echo "  medium    : $MED"
echo "  low       :  $LOW"
echo ""
echo "top rules (5)"
jq -r '.by_rule | to_entries | sort_by(.value) | reverse | .[0:5] | map("  \(.key) \(.value)") | .[]' "$OUTPUT_FILE"
echo ""
echo "top hosts (3 by cumulative score)"
jq -r '.top_targets | map("  \(.hostname)   score \(.score)") | .[]' "$OUTPUT_FILE"
echo "attack tactics covered : $TACTICS_COUNT"
echo "queue_assessment.json written"
