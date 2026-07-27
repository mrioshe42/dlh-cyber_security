#!/bin/bash
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 <file_path> <expected_sha256_hash>"; exit 1; }
[[ -f $1 ]] || { echo "File not found: $1"; exit 1; }

EXPECTED_HASH="${2,,}"
read -r ACTUAL_HASH _ < <(sha256sum "$1")

if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
    echo "INTEGRITY OK"
    exit 0
fi

echo "INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
exit 1
