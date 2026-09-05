#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

mkdir -p "$CATALOG_DIR"

ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"
EVENT_SCHEMA="$HANDOFF_DIR/schema/event_schema.json"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

for path in "$ENRICHED_EVENTS" "$EVENT_SCHEMA"; do
    if [ ! -f "$path" ]; then
        echo "Error: Required file not found: $path" >&2
        exit 1
    fi
done

jq -s '
  (if length == 1 and (.[0] | type == "array") then .[0] else . end)
  | map(. + {st: (.source_type // .sourcetype // .source // "unknown")})
  | group_by(.st)
  | map(
    . as $group
    | ($group | length) as $rc
    | ($group[0].st) as $st
    | ($group | [.[].keys[]] | unique) as $keys
    | ($keys | map(select(
        . as $k | ($group | map(has($k)) | add) / $rc >= 0.95
      ))) as $stable
    | ($keys | map(select(
        . as $k | ($group | map(.[$k] | tostring) | unique | length) > ($rc * 0.5)
      ))) as $high_card
    | if $st == "windows_json" then
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["signature", "anomaly", "behavioral", "correlation"],
          rationale: "High structural fidelity, rich field presence, and historical baseline support all detection paradigms.",
          recommended_attack_tactics: ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006"]
        }
      elif $st == "linux_text" then
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["signature", "anomaly", "behavioral", "correlation"],
          rationale: "Consistent log format with stable execution and auth fields enabling multi-paradigm coverage.",
          recommended_attack_tactics: ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005"]
        }
      elif $st == "suricata_alert" then
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["signature", "correlation"],
          rationale: "Pre-matched network signatures provide high-fidelity indicators suitable for signature matching and cross-source correlation.",
          recommended_attack_tactics: ["TA0001", "TA0011"]
        }
      elif $st == "firewall" then
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["anomaly", "correlation"],
          rationale: "Volume and connection metrics support statistical anomaly detection and multi-source pivoting.",
          recommended_attack_tactics: ["TA0001", "TA0010"]
        }
      elif $st == "pcap_flow" then
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["anomaly", "behavioral"],
          rationale: "Flow metadata lacks discrete command signatures but exhibits volumetric and behavioral baselines.",
          recommended_attack_tactics: ["TA0009", "TA0010"]
        }
      else
        {
          source_type: $st,
          record_count: $rc,
          stable_fields: $stable,
          high_cardinality_fields: $high_card,
          supported_detection_types: ["signature", "correlation"],
          rationale: "Default capability mapping based on generic log structure.",
          recommended_attack_tactics: ["TA0001"]
        }
      end
  )
' "$ENRICHED_EVENTS" > "$CATALOG_DIR/detection_matrix.json"

total_sources=$(jq length "$CATALOG_DIR/detection_matrix.json")

jq -r '.[] | "\(.source_type) \(.supported_detection_types | length) types [\(.supported_detection_types | join(" "))]"' "$CATALOG_DIR/detection_matrix.json" | while read -r line; do
    st=$(echo "$line" | cut -d' ' -f1)
    rest=$(echo "$line" | cut -d' ' -f2-)
    printf "%-16s %s\n" "$st" "$rest"
done

echo "$total_sources source types analyzed"
echo "detection_matrix.json written"
