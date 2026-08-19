#!/bin/bash
# Script Name: 10-rule_validation.sh
# Description: High-speed validation of custom MedDefense rules against PCAPs.
# Author: Massimo

set -uo pipefail

RULES_FILE="meddefense.rules"
DEST_RULES_DIR="/var/lib/suricata/rules"
LAB_DIR="/home/analyst/MedDefense_Lab/PCAPs"
LABELS_DIR="${LAB_DIR}/labels"

if [ -f "${RULES_FILE}" ]; then
    sudo cp -f "${RULES_FILE}" "${DEST_RULES_DIR}/"
else
    echo "[!] Error: ${RULES_FILE} not found." >&2
    exit 1
fi

TOTAL_RULES=6
PASSED_COUNT=0
FAILED_COUNT=0

echo "[*] Loading ${RULES_FILE}...          ${TOTAL_RULES} rules"
echo "[*] Running validation against labeled PCAPs (High-Speed Mode)..."

declare -A TEST_CASES=(
    ["9000001"]="meddev_egress.pcap|MEDDEV to Internet"
    ["9000002"]="guest_smb.pcap|Guest to SMB"
    ["9000003"]="large_outbound.pcap|Large Outbound From Server"
    ["9000004"]="dns_tunnel.pcap|DNS Tunneling Long Label"
    ["9000005"]="clinical_wrong_db.pcap|Clinical to Unauthorized DB"
    ["9000006"]="telnet_meddev.pcap|Telnet to MEDDEV"
)

SIDS=("9000001" "9000002" "9000003" "9000004" "9000005" "9000006")

for sid in "${SIDS[@]}"; do
    IFS='|' read -r pcap_name desc <<< "${TEST_CASES[$sid]}"
    PCAP_PATH="${LABELS_DIR}/${pcap_name}"
    if [ ! -f "${PCAP_PATH}" ]; then
        PCAP_PATH="${LAB_DIR}/${pcap_name}"
    fi

    TEMP_LOG_DIR="/tmp/suricata_val_${sid}"
    rm -rf "${TEMP_LOG_DIR}"
    mkdir -p "${TEMP_LOG_DIR}"

    HITS=0
    if [ -f "${PCAP_PATH}" ]; then
        suricata -S "${RULES_FILE}" -r "${PCAP_PATH}" -l "${TEMP_LOG_DIR}" > /dev/null 2>&1 || true
        
        if [ -f "${TEMP_LOG_DIR}/eve.json" ]; then
            HITS=$(jq --argjson sid "$sid" 'select(.event_type == "alert" and .alert.signature_id == $sid) | .alert.signature_id' "${TEMP_LOG_DIR}/eve.json" | wc -l)
        fi
    fi

    printf "sid %s %s\n" "$sid" "$desc"
    printf "  target: %s\n" "$pcap_name"
    printf "  expected: fire\n"

    if [ "$HITS" -gt 0 ]; then
        hit_label="hit"
        [ "$HITS" -gt 1 ] && hit_label="hits"
        printf "  observed: fire (%s %s)                PASS\n\n" "$HITS" "$hit_label"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        printf "  observed: did not fire                 FAIL\n\n"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

echo "Rules:  ${TOTAL_RULES}"
echo "Passed: ${PASSED_COUNT}"
echo "Failed: ${FAILED_COUNT}"

if [ "${FAILED_COUNT}" -gt 0 ]; then
    exit 1
else
    exit 0
fi
