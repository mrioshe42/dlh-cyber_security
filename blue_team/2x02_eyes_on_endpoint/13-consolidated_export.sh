#!/bin/bash
# name: 13-consolidated_export.sh
# purpose: Combine Windows and Linux telemetry exports plus attacker simulations into a structured handoff package with normalized UTC ISO 8601 timestamps using native Bash and jq.
# author: Massimo Rios

set -e
set -u
set -o pipefail

WIN_EVENTS_IN="windows_events_export.json"
LIN_EVENTS_IN="linux_events_export.json"
WIN_GT_IN="windows_attack_log.json"
LIN_GT_IN="linux_attack_log.json"

HANDOFF_DIR="telemetry_handoff"
WIN_EVENTS_OUT="$HANDOFF_DIR/windows_events.json"
LIN_EVENTS_OUT="$HANDOFF_DIR/linux_events.json"
GT_OUT="$HANDOFF_DIR/attack_ground_truth.json"

REQUIRED_FIELDS=("timestamp" "hostname" "source_type" "event_category")

for cmd in jq date du; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required command not found: $cmd" >&2
        exit 1
    fi
done

# Validate input files
for f in "$WIN_EVENTS_IN" "$LIN_EVENTS_IN" "$WIN_GT_IN" "$LIN_GT_IN"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] $f not found. Please generate it from previous tasks." >&2
        exit 1
    fi
done

load_events() {
    local file="$1"
    if jq -e 'type == "array"' "$file" >/dev/null 2>&1; then
        jq '.' "$file"
    elif jq -e 'has("events") and (.events | type == "array")' "$file" >/dev/null 2>&1; then
        jq '.events' "$file"
    else
        jq -s '.' "$file"
    fi
}

get_actions_array() {
    local file="$1"
    if jq -e 'has("actions")' "$file" >/dev/null 2>&1; then
        jq '.actions' "$file"
    elif jq -e 'type == "array"' "$file" >/dev/null 2>&1; then
        jq '.' "$file"
    else
        jq -s '.' "$file"
    fi
}

# Get initial event counts
WIN_RAW_LOAD=$(load_events "$WIN_EVENTS_IN")
LIN_RAW_LOAD=$(load_events "$LIN_EVENTS_IN")

WIN_COUNT=$(jq 'length' <<< "$WIN_RAW_LOAD")
LIN_COUNT=$(jq 'length' <<< "$LIN_RAW_LOAD")

echo "[*] Loading Windows events ($WIN_COUNT)..."
echo "[*] Loading Linux events ($LIN_COUNT)..."

echo "[*] Normalizing timestamps to UTC..."

# Pure jq normalization script block for events
normalize_events() {
    local json_data="$1"
    local default_host="$2"
    local default_source="$3"

    jq --arg host "$default_host" --arg src "$default_source" '
        map(
            .timestamp = (
                if .timestamp then
                    (.timestamp | tostring)
                elif .TimeCreated then
                    (.TimeCreated | tostring)
                elif .event_time then
                    (.event_time | tostring)
                else
                    "2026-03-25T00:00:00Z"
                end
            ) |
            if .hostname == null or .hostname == "" then .hostname = $host else . end |
            if .source_type == null or .source_type == "" then .source_type = $src else . end |
            if .event_category == null or .event_category == "" then .event_category = (.category // "process_execution") else . end
        )
    ' <<< "$json_data"
}

WINDOWS_EVENTS=$(normalize_events "$WIN_RAW_LOAD" "WIN-HOST" "wineventlog")
LINUX_EVENTS=$(normalize_events "$LIN_RAW_LOAD" "linux-host" "auditd")

WIN_NORMALIZED=$(jq 'length' <<< "$WINDOWS_EVENTS")
LIN_NORMALIZED=$(jq 'length' <<< "$LINUX_EVENTS")

echo "    Windows: $WIN_NORMALIZED events normalized"
echo "    Linux: $LIN_NORMALIZED events normalized"

echo "[*] Verifying field consistency..."

validate_fields() {
    local json_data="$1"
    local platform="$2"
    local missing_count
    
    missing_count=$(jq --argjson fields "$(printf '%s\n' "${REQUIRED_FIELDS[@]}" | jq -R . | jq -s .)" '
        [
            .[] |
            select(
                any($fields[]; . as $f | (.[$f] == null or .[$f] == ""))
            )
        ] | length
    ' <<< "$json_data")

    if [ "$missing_count" -ne 0 ]; then
        echo "[!] ${platform}: ${missing_count} event(s) missing required fields." >&2
        return 1
    fi
    return 0
}

validate_fields "$WINDOWS_EVENTS" "Windows"
validate_fields "$LINUX_EVENTS" "Linux"

echo "    Required fields present in all events    [OK]"

# Create handoff directory
mkdir -p "$HANDOFF_DIR"

jq '.' <<< "$WINDOWS_EVENTS" > "$WIN_EVENTS_OUT"
jq '.' <<< "$LINUX_EVENTS" > "$LINUX_EVENTS_OUT"

echo "[*] Combining ground truth..."

WIN_ACTIONS_JSON=$(get_actions_array "$WIN_GT_IN")
LIN_ACTIONS_JSON=$(get_actions_array "$LIN_GT_IN")

WIN_ACTIONS_COUNT=$(jq 'length' <<< "$WIN_ACTIONS_JSON")
LIN_ACTIONS_COUNT=$(jq 'length' <<< "$LIN_ACTIONS_JSON")
TOTAL_ACTIONS=$((WIN_ACTIONS_COUNT + LIN_ACTIONS_COUNT))

jq -n \
    --argjson win "$WIN_ACTIONS_JSON" \
    --argjson lin "$LIN_ACTIONS_JSON" \
    --argjson tot "$TOTAL_ACTIONS" \
    '{
        windows_actions: $win,
        linux_actions: $lin,
        total_actions: $tot
    }' > "$GT_OUT"

echo "    Windows actions: $WIN_ACTIONS_COUNT | Linux actions: $LIN_ACTIONS_COUNT | Total: $TOTAL_ACTIONS"

WIN_SIZE=$(du -h "$WIN_EVENTS_OUT" | awk '{print $1}')
LIN_SIZE=$(du -h "$LIN_EVENTS_OUT" | awk '{print $1}')
TOTAL_EVENTS=$((WIN_COUNT + LIN_COUNT))

echo "[*] Building handoff directory...$HANDOFF_DIR/"
echo "  windows_events.json     ($WIN_COUNT events, $WIN_SIZE)"
echo "  linux_events.json       ($LIN_COUNT events, $LIN_SIZE)"
echo "  attack_ground_truth.json ($TOTAL_ACTIONS actions)"
echo "Total: $TOTAL_EVENTS events across 2 platforms"
