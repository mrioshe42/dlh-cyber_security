#!/bin/bash
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 <file_path> <expected_sha256_hash>"; exit 1; }
FILE="$1"
ARG2="$2"
[[ -f "$FILE" ]] || { echo "File not found: $FILE"; exit 1; }

EXPECTED_HASH="${ARG2,,}"
ACTUAL_HASH=$(sha256sum "$FILE" | cut -d' ' -f1)

if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
    echo "INTEGRITY OK"
    exit 0
fi

echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
exit 1
