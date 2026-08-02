#!/bin/bash

set -euo pipefail

REPORT="${1:-}"
HARDENING_INDEX=$(grep -E "^hardening_index=" "$REPORT" | head -n1 | cut -d '=' -f2 | tr -d '[:space:]')
HARDENING_INDEX=${HARDENING_INDEX:-0}

FINDINGS=$(awk -F'=' '
/^(warning|suggestion|manual_check)\[\]=/ {
    sev = $1
    sub(/\[\]/, "", sev)
    rest = $2
    n = split(rest, parts, "|")
    test_id = parts[1]
    msg = ""
    for (i = 2; i <= n; i++) {
        msg = (i == 2) ? parts[i] : msg "|" parts[i]
    }
    print sev "\t" test_id "\t" msg
}' "$REPORT" | jq -R -s '[split("\n")[] | select(length > 0) | split("\t") | {severity: .[0], test_id: .[1], message: .[2]}]')

jq -n \
    --argjson index "$HARDENING_INDEX" \
    --argjson findings "$FINDINGS" \
    '{
        hardening_index: $index,
        findings: $findings
    }'
