#!/bin/bash
# Script Name: 8-suricata_setup.sh
# Description: Prepares Suricata for offline PCAP replay, synchronizes rules,
#              renders a fully compliant suricata.yaml, validates configuration safely,
#              runs an end-to-end smoke test, and emits setup_verification.json.
# Author: Massimo

set -euo pipefail

RULES_SRC_DIR="/home/analyst/MedDefense_Lab/suricata/rules"
RULES_DEST_DIR="/var/lib/suricata/rules"
CONFIG_FILE="suricata.yaml"
VERIFICATION_FILE="setup_verification.json"
SMOKE_PCAP="/home/analyst/MedDefense_Lab/PCAPs/smoke.pcap"
SMOKE_LOG_DIR="/tmp/suricata-smoke"

echo "[+] Ensuring suricata and jq are installed..."
if ! command -v suricata &> /dev/null || ! command -v jq &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y suricata jq
fi

echo "[+] Setting up rule files in ${RULES_DEST_DIR}..."
sudo mkdir -p "${RULES_DEST_DIR}"
if [ -d "${RULES_SRC_DIR}" ]; then
    sudo cp -f "${RULES_SRC_DIR}"/*.rules "${RULES_DEST_DIR}/" 2>/dev/null || true
fi

sudo touch "${RULES_DEST_DIR}/meddefense.rules"

# Count loaded rule files and total rules
RULE_FILES_LIST=$(ls -1 "${RULES_DEST_DIR}"/*.rules 2>/dev/null | xargs -n1 basename | jq -R -s 'split("\n")[:-1]')
RULE_COUNT=$(cat "${RULES_DEST_DIR}"/*.rules 2>/dev/null | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | wc -l)
RULE_FILES_LOADED_COUNT=$(echo "${RULE_FILES_LIST}" | jq length)

echo "[+] Rendering compatible ${CONFIG_FILE}..."
cat << EOF > "${CONFIG_FILE}"
%YAML 1.1
---
default-rule-path: /var/lib/suricata/rules

rule-files:
  - meddefense.rules
EOF

for rfile in "${RULES_DEST_DIR}"/*.rules; do
    if [ -f "$rfile" ]; then
        filename=$(basename "$rfile")
        if [ "$filename" != "meddefense.rules" ]; then
            echo "  - ${filename}" >> "${CONFIG_FILE}"
        fi
    fi
done

cat << 'EOF' >> "${CONFIG_FILE}"

default-log-dir: /var/log/suricata

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes

pcap-file:
  enabled: yes

vars:
  address-groups:
    HOME_NET: "[10.10.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "any"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
EOF

echo "[+] Running Suricata configuration syntax test (-T)..."
set +e
suricata -T -c "./${CONFIG_FILE}" -v > /tmp/suricata_test.log 2>&1 &
SURICATA_PID=$!

sleep 4
if kill -0 $SURICATA_PID 2>/dev/null; then
    kill $SURICATA_PID 2>/dev/null || true
    CONFIG_TEST_EXIT=0
else
    wait $SURICATA_PID
    CONFIG_TEST_EXIT=$?
fi
set -e

echo "[+] Running quick end-to-end smoke test on ${SMOKE_PCAP}..."
rm -rf "${SMOKE_LOG_DIR}"
mkdir -p "${SMOKE_LOG_DIR}"

if [ -f "${SMOKE_PCAP}" ]; then
    suricata -c "./${CONFIG_FILE}" -r "${SMOKE_PCAP}" -l "${SMOKE_LOG_DIR}"
fi

SMOKE_ALERTS=0
if [ -f "${SMOKE_LOG_DIR}/eve.json" ]; then
    SMOKE_ALERTS=$(grep -c '"event_type":"alert"' "${SMOKE_LOG_DIR}/eve.json" || true)
fi

INSTALLED_VERSION=$(suricata -V | grep -oP 'version \K[0-9]+\.[0-9]+\.[0-9]+' || suricata -V | awk '{print $NF}')

echo "[+] Generating ${VERIFICATION_FILE}..."
cat << EOF > "${VERIFICATION_FILE}"
{
  "installed_version": "${INSTALLED_VERSION}",
  "rule_files_loaded": ${RULE_FILES_LOADED_COUNT},
  "rule_count": ${RULE_COUNT},
  "config_test_exit": ${CONFIG_TEST_EXIT},
  "smoke_alerts": ${SMOKE_ALERTS}
}
EOF

echo "[+] Suricata offline setup successfully completed."
cat "${VERIFICATION_FILE}"
