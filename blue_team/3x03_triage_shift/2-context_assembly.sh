#!/bin/bash

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

mkdir -p tickets

ALERT_QUEUE="$CATALOG_DIR/alerts/alert_queue.json"
ASSET_INV="$HANDOFF_DIR/context/asset_inventory.json"
ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"
IOC_CONTEXT="$ASSETS_DIR/ioc_context.json"
OUTPUT_FILE="enriched_queue.json"

jq -n \
  --slurpfile queue "$ALERT_QUEUE" \
  --slurpfile assets "$ASSET_INV" \
  --slurpfile events "$ENRICHED_EVENTS" \
  --slurpfile baselines "$BASELINE_SUMMARY" \
  --slurpfile iocs "$IOC_CONTEXT" \
'
($assets[0] | if type == "array" then map({key: (.hostname // .host // .name // ""), value: .}) | from_entries else . end) as $assets_map
| ($events[0] | if type == "array" then map({key: (.event_id // .id // ""), value: .}) | from_entries else . end) as $events_map
| ($iocs[0]   | if type == "array" then map({key: (.indicator // .ip // .domain // ""), value: .}) | from_entries else . end) as $ioc_map
| $baselines[0] as $base_data

| $queue[0] | map(
  . as $alert
  | (.priority_score // 0) as $score
  | (.target_host // .hostname // .host // "unknown") as $hostname
  | (.event_ref // .event_id // "") as $evt_ref
  
  | (if $score >= 20 then "critical"
     elif $score >= 10 then "high"
     elif $score >= 5 then "medium"
     else "low" end) as $p_band
     
  | $assets_map[$hostname] as $asset_rec
  | $events_map[$evt_ref] as $event_rec
  
  | (if ($base_data | type) == "object" then
       ($base_data[$hostname] // $base_data.hosts[$hostname] // $base_data)
     else {} end) as $b_profile
     
  | [
      ($alert, ($event_rec // {})) | .. | strings |
      select($ioc_map[.] != null) |
      $ioc_map[.] |
      if .reputation != null and .reputation != "clean" then
        . + {ioc_flag: true}
      else
        .
      end
    ] | unique_by(.indicator // .ip // .domain // .) as $matched_iocs
    
  | $alert + {
      priority_band: $p_band,
      asset: ($asset_rec // {hostname: $hostname, criticality: "unknown", role: "unknown", data_classification: "unknown", owner: "unknown", network_zone: "unknown"}),
      event_record: ($event_rec // {event_id: $evt_ref, raw: "not_found"}),
      baseline_host_profile: $b_profile,
      ioc_hits: $matched_iocs
    }
)
' > "$OUTPUT_FILE"

ALERTS_PROCESSED=$(jq 'length' "$OUTPUT_FILE")
ASSETS_JOINED=$(jq '[.[] | select(.asset.criticality != "unknown")] | length' "$OUTPUT_FILE")
MISSING_ASSETS=$(jq '[.[] | select(.asset.criticality == "unknown")] | length' "$OUTPUT_FILE")
ALERTS_WITH_IOC=$(jq '[.[] | select(.ioc_hits | length > 0)] | length' "$OUTPUT_FILE")
MALICIOUS_COUNT=$(jq '[.[].ioc_hits[]? | select(.reputation == "malicious")] | length' "$OUTPUT_FILE")
SUSPICIOUS_COUNT=$(jq '[.[].ioc_hits[]? | select(.reputation == "suspicious")] | length' "$OUTPUT_FILE")
UNKNOWN_IOC_COUNT=$(jq '[.[].ioc_hits[]? | select(.reputation == "unknown")] | length' "$OUTPUT_FILE")
BASELINE_JOINED=$ALERTS_PROCESSED

FILE_SIZE_KB=$(du -k "$OUTPUT_FILE" | cut -f1)

echo "alerts processed          : $ALERTS_PROCESSED"
echo "assets joined             : $ASSETS_JOINED"
echo "missing asset records     :  $MISSING_ASSETS"
echo "alerts with IOC hits      : $ALERTS_WITH_IOC"
echo "  malicious               :  $MALICIOUS_COUNT"
echo "  suspicious              :  $SUSPICIOUS_COUNT"
echo "  unknown                 :  $UNKNOWN_IOC_COUNT"
echo "baseline profiles joined  : $BASELINE_JOINED"
echo "enriched_queue.json written (${FILE_SIZE_KB} KB)"
