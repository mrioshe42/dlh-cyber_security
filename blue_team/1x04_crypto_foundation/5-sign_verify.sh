#!/bin/bash
set -euo pipefail

ARG1="${1:-}"
MODE="${ARG1,,}"

if [[ "$MODE" == "sign" && $# -eq 3 ]]; then
    FILE="$2"
    KEY="$3"
    [[ -f "$FILE" && -f "$KEY" ]] || { echo "[ERROR] File or key missing."; exit 1; }
    openssl dgst -sha256 -sign "$KEY" -out "$FILE.sig" "$FILE"
    echo "[SUCCESS] Signature saved: $FILE.sig"
elif [[ "$MODE" == "verify" && $# -eq 4 ]]; then
    FILE="$2"
    SIG="$3"
    KEY="$4"
    [[ -f "$FILE" && -f "$SIG" && -f "$KEY" ]] || { echo "[ERROR] File, signature, or key missing."; exit 1; }
    openssl dgst -sha256 -verify "$KEY" -signature "$SIG" "$FILE"
else
    echo "Usage:"
    echo "  Sign:   $0 sign <file_path> <private_key_path>"
    echo "  Verify: $0 verify <file_path> <signature_path> <public_key_path>"
    exit 1
fi
