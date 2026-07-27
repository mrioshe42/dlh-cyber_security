#!/bin/bash
set -euo pipefail

MODE="${1,,}"

if [[ "$MODE" == "sign" && $# -eq 3 ]]; then
    [[ -f $2 && -f $3 ]] || { echo "[ERROR] File or key missing."; exit 1; }
    openssl dgst -sha256 -sign "$3" -out "$2.sig" "$2"
    echo "[SUCCESS] Signature saved: $2.sig"
elif [[ "$MODE" == "verify" && $# -eq 4 ]]; then
    [[ -f $2 && -f $3 && -f $4 ]] || { echo "[ERROR] File, signature, or key missing."; exit 1; }
    openssl dgst -sha256 -verify "$4" -signature "$3" "$2"
else
    echo "Usage:"
    echo "  Sign:   $0 sign <file_path> <private_key_path>"
    echo "  Verify: $0 verify <file_path> <signature_path> <public_key_path>"
    exit 1
fi
