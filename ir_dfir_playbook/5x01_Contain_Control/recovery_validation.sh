#!/bin/bash
set -u

API_URL="${1:-http://127.0.0.1:8080}"
EVIDENCE_STORE="${2:-/evidence/IR-20260414-01}"
FAILED=()

check() {
  if [ "$2" -eq 0 ]; then
    echo "[PASS] $1"
  else
    echo "[FAIL] $1"
    FAILED+=("$1")
  fi
}

check_process_tree() {
  for host in WST-WS-031 WST-WS-017 LIS-WSIDE-01; do
    local matches=$(curl -s "${API_URL}/endpoint/processtree/${host}.json" | jq '.data.process_trees_matching.powershell_parent_msbuild_child // 0')
    [ "$matches" -eq 0 ] || return 1
  done
  return 0
}

check_netflow() {
  local data=$(curl -s "${API_URL}/siem/netflow.json")
  local p185=$(echo "$data" | jq '.data.connections_to_185_220_101_47.packets // 0')
  local p91=$(echo "$data" | jq '.data.connections_to_91_234_99_107.packets // 0')
  [ "$p185" -eq 0 ] && [ "$p91" -eq 0 ]
}

check_persistence() {
  for host in WST-WS-031 WST-WS-017 LIS-WSIDE-01; do
    local data=$(curl -s "${API_URL}/endpoint/persistence/${host}.json")
    local tasks=$(echo "$data" | jq '.data.scheduled_tasks_with_guid_names | length')
    local payloads=$(echo "$data" | jq '[.data.temp_dropped_payloads[] | select(. == "present")] | length')
    [ "$tasks" -eq 0 ] && [ "$payloads" -eq 0 ] || return 1
  done
  return 0
}

check_services() {
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${API_URL}/service/epic-api/health")" -eq 200 ] && \
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${API_URL}/service/lis-api/health")" -eq 200 ]
}

check_detection() {
  curl -s "${API_URL}/siem/detection/wz-edr-100041/synthetic.json" | jq '.data.synthetic_matched' | grep -q true
}

check_hashes() {
  [ -f "${EVIDENCE_STORE}/hashes.txt" ] || return 1
  cd "${EVIDENCE_STORE}" && sha256sum -c hashes.txt > /dev/null 2>&1
}

check "process tree: no powershell->msbuild in last 24h" "$(check_process_tree; echo $?)"
check "netflow: no outbound to C2 IPs in last 24h" "$(check_netflow; echo $?)"
check "persistence: no artifacts found" "$(check_persistence; echo $?)"
check "service health: epic and lis respond 200" "$(check_services; echo $?)"
check "detection: wz-edr-100041 active" "$(check_detection; echo $?)"
check "evidence hashes: all artifacts match SHA-256" "$(check_hashes; echo $?)"

if [ ${#FAILED[@]} -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
else
  echo "FAILED: ${FAILED[*]}"
  exit 1
fi
