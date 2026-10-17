#!/bin/bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HASHES_FILE="${SCRIPT_DIR}/hashes.txt"
VERIFICATION_LOG="${SCRIPT_DIR}/verification_log.txt"

declare -a ARTIFACTS=(
  "ART-001:wst-ws-031.dd:${SCRIPT_DIR}/5x02/wst-ws-031.dd"
  "ART-002:wst-ws-031.mem:${SCRIPT_DIR}/5x02/wst-ws-031.mem"
  "ART-003:wst-ws-017.mem:${SCRIPT_DIR}/5x02/wst-ws-017.mem"
)

log_event() {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | ${USER:-unknown} | $1 | $2 | $3 | $4" >> "${VERIFICATION_LOG}"
}

[ ! -f "${VERIFICATION_LOG}" ] && echo "# Verification Log -- IR-2026-0414-01" > "${VERIFICATION_LOG}"

if [ ! -f "${HASHES_FILE}" ]; then
  baseline_ok=1
  > "${HASHES_FILE}"

  for artifact in "${ARTIFACTS[@]}"; do
    IFS=':' read -r art_id art_name art_path <<< "$artifact"

    if [ ! -f "$art_path" ]; then
      log_event "$art_id" "MISSING" "—" "File not found"
      baseline_ok=0
      continue
    fi

    hash=$(sha256sum "$art_path" | awk '{print $1}')
    echo "[BASELINE_SET] ${art_id} ${art_name}  ${hash:0:16}..."
    echo "${hash}  ${art_name}" >> "${HASHES_FILE}"
    log_event "$art_id" "BASELINE_SET" "$hash" "Baseline established"
  done

  [ $baseline_ok -eq 1 ] && echo "Baseline written to hashes.txt" && exit 0 || exit 1
fi

all_pass=1

for artifact in "${ARTIFACTS[@]}"; do
  IFS=':' read -r art_id art_name art_path <<< "$artifact"

  [ ! -f "$art_path" ] && { log_event "$art_id" "MISSING" "—" "File not found"; all_pass=0; continue; }

  computed=$(sha256sum "$art_path" | awk '{print $1}')
  expected=$(grep "  ${art_name}$" "${HASHES_FILE}" 2>/dev/null | awk '{print $1}')

  [ -z "$expected" ] && { log_event "$art_id" "MISSING_BASELINE" "$computed" "No baseline"; all_pass=0; continue; }

  if [ "$computed" = "$expected" ]; then
    echo "[PASS] ${art_id} ${art_name}  ${expected:0:16}..."
    log_event "$art_id" "PASS" "$expected" ""
  else
    echo "[FAIL] ${art_id} ${art_name}  expected=${expected:0:16}... got=${computed:0:16}..."
    log_event "$art_id" "FAIL" "$expected / $computed" "INTEGRITY VIOLATION"
    all_pass=0
  fi
done

[ $all_pass -eq 1 ] && exit 0 || exit 1
