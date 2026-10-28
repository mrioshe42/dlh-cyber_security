#!/bin/bash

P=0 F=0
echo "=== Recovery Validation: IR-2026-0420-01 ==="
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

! wevtutil qe System "/q:*[System[EventID=7045]]" 2>/dev/null | grep -qi "svchost32\|WinHealthSvc" && \
  { echo "[PASS] beacon: no svchost32.exe in logs"; ((P++)); } || \
  { echo "[FAIL] beacon: found service events"; ((F++)); }

! netstat -an 2>/dev/null | grep -q "45.152.66.114\|staging.office365-cdn" && \
  { echo "[PASS] c2: no C2 traffic"; ((P++)); } || \
  { echo "[FAIL] c2: active C2 connections"; ((F++)); }

[ $(find /mnt/evidence -name "encryption_staging.ps1" 2>/dev/null | wc -l) -eq 0 ] && \
  { echo "[PASS] ransomware: no staging scripts"; ((P++)); } || \
  { echo "[FAIL] ransomware: staging scripts found"; ((F++)); }

SVC_OK=1; for S in epic-api lis-api scheduling-api; do \
  [ "$(curl -s -o /dev/null -w %{http_code} http://10.42.50.100:8080/$S/health 2>/dev/null)" = "200" ] || SVC_OK=0; done
[ $SVC_OK -eq 1 ] && \
  { echo "[PASS] services: all endpoints 200"; ((P++)); } || \
  { echo "[FAIL] services: endpoints down"; ((F++)); }

[ $(curl -s http://10.42.1.100:5000/api/agents/health 2>/dev/null | jq -r '.agents[] | select(.status=="healthy")' 2>/dev/null | wc -l) -ge 5 ] && \
  { echo "[PASS] edr: 5/5 hosts reporting"; ((P++)); } || \
  { echo "[FAIL] edr: hosts not reporting"; ((F++)); }

RULE=$(curl -s http://10.42.100.10:9200/rules/cobalt_strike_beacon 2>/dev/null | jq -r '.status' 2>/dev/null)
if [ "$RULE" = "active" ]; then
  TEST=$(curl -s -X POST http://10.42.100.10:9200/_test/detections -H "Content-Type: application/json" \
    -d '{"process":"svchost32.exe","parent":"services.exe"}' 2>/dev/null | jq -r '.matched_rule' 2>/dev/null)
  [ "$TEST" = "cobalt_strike_beacon" ] && \
    { echo "[PASS] detection: rule active + synthetic hit"; ((P++)); } || \
    { echo "[FAIL] detection: rule active but no test hit"; ((F++)); }
else
  echo "[FAIL] detection: rule not active"; ((F++))
fi

sha256sum -c /evidence/IR-2026-0420-01/hashes.txt 2>/dev/null | grep -q "OK$" && \
  { echo "[PASS] evidence: hashes match baseline"; ((P++)); } || \
  { echo "[FAIL] evidence: hash mismatch"; ((F++)); }

echo ""
echo "=== Results: $P PASS, $F FAIL ==="
[ $F -eq 0 ] && { echo "ALL CHECKS PASSED"; exit 0; } || { echo "$F FAILED"; exit 1; }
