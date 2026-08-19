#!/bin/bash
# Script Name: 9-suricata_analysis.sh
# Description: Replays a PCAP through Suricata, parses eve.json alerts, maps
#              them using signature_categories.json, aggregates statistics, 
#              and generates suricata_alerts.json, $1 
# Author: Massimo

set -euo pipefail

PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"
CONFIG_FILE="suricata.yaml"
OUTPUT_DIR="/tmp/suricata-analysis-$$"
VERIFICATION_FILE="suricata_alerts.json"
CAT_MAP_FILE="/home/analyst/MedDefense_Lab/suricata/signature_categories.json"
if [ ! -f "$CAT_MAP_FILE" ]; then
    CAT_MAP_FILE="signature_categories.json"
fi

if [ ! -f "$CAT_MAP_FILE" ]; then
    echo '{}' > "/tmp/empty_sig_map.json"
    CAT_MAP_FILE="/tmp/empty_sig_map.json"
fi

echo "[+] Starting Suricata analysis on PCAP: ${PCAP_PATH}"
if [ ! -f "${PCAP_PATH}" ]; then
    echo "[!] Error: PCAP file not found at ${PCAP_PATH}" >&2
    exit 1
fi

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Run Suricata offline PCAP replay
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[+] Running suricata replay engine..."
suricata -c "./${CONFIG_FILE}" -r "${PCAP_PATH}" -l "${OUTPUT_DIR}"
FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

EVE_LOG="${OUTPUT_DIR}/eve.json"
if [ ! -f "${EVE_LOG}" ]; then
    echo "[!] Warning: eve.json not generated. No alerts found or engine error."
    jq -n \
        --arg pcap "$PCAP_PATH" \
        --arg start "$STARTED_AT" \
        --arg finish "$FINISHED_AT" \
        '{
          pcap: $pcap,
          started_at: $start,
          finished_at: $finish,
          total_alerts: 0,
          unique_signatures: 0,
          severity_distribution: {},
          by_category: {},
          top_sources: [],
          top_destinations: [],
          alerts: []
        }' > "${VERIFICATION_FILE}"
    cat "${VERIFICATION_FILE}"
    exit 0
fi

echo "[+] Parsing and classifying alerts from eve.json..."

# Extract alert items into a temporary JSON array file line-by-line safely
jq -c 'select(.event_type == "alert") | {
    timestamp: .timestamp,
    src_ip: .src_ip,
    src_port: .src_port,
    dst_ip: .dst_ip,
    dst_port: .dst_port,
    proto: .proto,
    sig: .alert.signature,
    sig_id: .alert.signature_id,
    category: .alert.category,
    severity: .alert.severity
}' "${EVE_LOG}" | jq -s '.' > "${OUTPUT_DIR}/parsed_alerts.json"

jq \
    --arg pcap "$PCAP_PATH" \
    --arg start "$STARTED_AT" \
    --arg finish "$FINISHED_AT" \
    --slurpfile sigmap "${CAT_MAP_FILE}" \
    '
    # sigmap is loaded as a 1-element array containing the parsed JSON object
    ($sigmap[0] // {}) as $map |

    # Map each alert to include classification category
    def classify($sig):
        if $map[$sig] then $map[$sig]
        elif ($sig | ascii_downcase | contains("scan") or contains("probe")) then "reconnaissance"
        elif ($sig | ascii_downcase | contains("exploit") or contains("exec") or contains("overflow")) then "exploit"
        elif ($sig | ascii_downcase | contains("smb") or contains("psexec") or contains("lateral") or contains("wmi")) then "lateral_movement"
        elif ($sig | ascii_downcase | contains("dns") or contains("exfil") or contains("tunnel") or contains("txt")) then "exfiltration"
        elif ($sig | ascii_downcase | contains("cobalt") or contains("beacon") or contains("trojan") or contains("malware") or contains("c2")) then "malware_c2"
        elif ($sig | ascii_downcase | contains("policy") or contains("audit")) then "policy_violation"
        else "other"
        end;

    # Process array items with category added
    [.[] | . + {classification: classify(.sig)}] as $alerts |
    
    $alerts as $all |
    {
      pcap: $pcap,
      started_at: $start,
      finished_at: $finish,
      total_alerts: ($all | length),
      unique_signatures: ([ $all[].sig ] | unique | length),
      severity_distribution: (
        reduce $all[] as $item ({}; .[$item.severity | tostring] += 1)
      ),
      by_category: (
        reduce $all[] as $item ({}; .[$item.classification] += 1)
      ),
      top_sources: [
        ($all | group_by(.src_ip) | map({ip: .[0].src_ip, count: length}) | sort_by(-.count)[0:10][])
      ],
      top_destinations: [
        ($all | group_by(.dst_ip) | map({ip: .[0].dst_ip, count: length}) | sort_by(-.count)[0:10][])
      ],
      alerts: $all
    }
    ' "${OUTPUT_DIR}/parsed_alerts.json" > "${VERIFICATION_FILE}"

echo "[+] Analysis complete. Report generated at: ${VERIFICATION_FILE}"
cat "${VERIFICATION_FILE}"
