#!/bin/bash
set -euo pipefail

[[ $# -eq 3 ]] || { echo "Usage: $0 <in_file> <out_file> <cbc|gcm>"; exit 1; }
[[ -f $1 ]] || { echo "Input file '$1' not found."; exit 1; }

ARG3="$3"
MODE="${ARG3,,}"
[[ "$MODE" =~ ^(cbc|gcm)$ ]] || { echo "Mode must be cbc or gcm."; exit 1; }

[[ -z "${MEDDEFENSE_CRYPTO_KEY:-}" ]] && { read -sp "Passphrase: " MEDDEFENSE_CRYPTO_KEY; echo; }

echo "Encrypting $1 using AES-256-${MODE^^}..."
openssl enc "-aes-256-$MODE" -salt -in "$1" -out "$2" -pass pass:"$MEDDEFENSE_CRYPTO_KEY"
