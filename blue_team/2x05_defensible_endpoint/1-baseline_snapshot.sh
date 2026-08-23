#!/bin/bash
# Script Name: 1-baseline_snapshot.sh
# Description: Runs Lynis security audit on hawthorne-app-01, extracts the
#              Hardening Index, and outputs structured JSON baseline data.
# Exit Codes:  0 = Success, 1 = Controlled Failure, 2 = Environment Error

set -uo pipefail
# capstone/baseline/lynis_baseline.log
BASELINE_DIR="./capstone/baseline"
LOG_PATH="${BASELINE_DIR}/lynis_baseline.log"
JSON_PATH="${BASELINE_DIR}/baseline_linux.json"

if ! mkdir -p "$BASELINE_DIR"; then
    echo "[-] Error: Failed to create directory $BASELINE_DIR" >&2
    exit 2
fi

if ! command -v lynis &>/dev/null; then
    echo "[-] Error: 'lynis' command not found. Please install Lynis." >&2
    exit 2
fi

echo "[+] Running Lynis security audit on $(hostname)..."

lynis audit system --quick --no-colors > "$LOG_PATH" 2>&1 || true

if [ ! -f "$LOG_PATH" ]; then
    echo "[-] Error: Lynis log file was not generated at $LOG_PATH" >&2
    exit 1
fi

HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
LYNIS_VERSION=$(lynis show version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || echo "Unknown")
HARDENING_INDEX=$(grep -oP 'Hardening index\s*:\s*\K[0-9]+' "$LOG_PATH" || echo "0")
WARNINGS_COUNT=$(grep -c '^\s*!\s' "$LOG_PATH" || echo "0")
SUGGESTIONS_COUNT=$(grep -c '^\s*\-\s' "$LOG_PATH" || echo "0")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --arg lynis_version "$LYNIS_VERSION" \
    --argjson hardening_index "$HARDENING_INDEX" \
    --argjson warnings "$WARNINGS_COUNT" \
    --argjson suggestions "$SUGGESTIONS_COUNT" \
    --arg log_path "$LOG_PATH" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        lynis_version: $lynis_version,
        hardening_index: $hardening_index,
        warnings_count: $warnings,
        suggestions_count: $suggestions,
        log_path: $log_path
    }' > "$JSON_PATH"

if [ -f "$JSON_PATH" ]; then
    echo "[+] Linux baseline snapshot complete. Evidence saved to $JSON_PATH"
    exit 0
else
    echo "[-] Error: Failed to write Linux baseline JSON." >&2
    exit 1
fi
