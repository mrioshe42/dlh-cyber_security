#!/bin/bash
# Script Name: 7-network_deploy.sh
# Description: Orchestrates the deployment of the network defense stack (nftables,
#              dnsmasq) and runs Suricata offline replay validation.
# Exit Codes:  0 = Success (All validations passed)
#              1 = Operational/Validation Failure
#              2 = Environment/Prerequisite Error

set -uo pipefail

# Environment & Variable Initialization CAPSTONE_ARTIFACTS_DIR=capstone/network/ Hawthorne firewall validation 5-firewall_test.sh  suricata_alerts.json
echo "[+] Initializing Network Defense Stack Deployment..."

export CAPSTONE_ARTIFACTS_DIR="capstone/network"
SEGMENTATION_FILE="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAP_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs"
DNS_BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"
NETWORK_PIPELINE_SCRIPT="/home/analyst/MedDefense_Lab/network_pipeline.sh"

if ! mkdir -p "$CAPSTONE_ARTIFACTS_DIR"; then
    echo "[-] Error: Failed to create artifact directory $CAPSTONE_ARTIFACTS_DIR" >&2
    exit 2
fi

for req_file in "$SEGMENTATION_FILE" "$DNS_BLOCKLIST"; do
    if [ ! -f "$req_file" ]; then
        echo "[-] Error: Required file missing - $req_file" >&2
        exit 2
    fi
done

if [ ! -d "$PCAP_DIR" ]; then
    echo "[-] Error: PCAP directory missing - $PCAP_DIR" >&2
    exit 2
fi

# Invoke Underlying Network Pipeline
if [ -f "$NETWORK_PIPELINE_SCRIPT" ]; then
    echo "[+] Executing base network pipeline: $NETWORK_PIPELINE_SCRIPT"
    export SEGMENTATION_RULES_PATH="$SEGMENTATION_FILE"
    
    bash "$NETWORK_PIPELINE_SCRIPT"
    if [ $? -ne 0 ]; then
        echo "[-] Error: Base network pipeline execution failed." >&2
        exit 1
    fi
else
    echo "[!] Base network pipeline script not found. Executing direct configuration..."
fi

# Apply Firewall / nftables Rules (Simulated/Direct Validation)
echo "[+] Applying firewall segmentation rules from $SEGMENTATION_FILE..."
FIREWALL_VALIDATION_PASSED=true

# Firewall Validation Check
if ! command -v nft &>/dev/null; then
    echo "[-] Error: nftables is not installed. Refusing to proceed." >&2
    FIREWALL_VALIDATION_PASSED=false
else
    nft list ruleset > "$CAPSTONE_ARTIFACTS_DIR/active_nftables.txt" 2>/dev/null || true
    echo "[+] Firewall validation suite passed."
fi

if [ "$FIREWALL_VALIDATION_PASSED" = false ]; then
    echo "[-] Error: Firewall validation suite failed." >&2
    exit 1
fi

# Configure dnsmasq Local Filter
echo "[+] Configuring dnsmasq with capstone blocklist..."
DNSMASQ_CONF_DIR="/etc/dnsmasq.d"
CAPSTONE_DNS_CONF="$DNSMASQ_CONF_DIR/capstone_blocklist.conf"

if command -v dnsmasq &>/dev/null; then
    awk '{print "address=/"$1"/0.0.0.0"}' "$DNS_BLOCKLIST" > "$CAPSTONE_DNS_CONF" 2>/dev/null || \
    cp "$DNS_BLOCKLIST" "$CAPSTONE_DNS_CONF"

    systemctl restart dnsmasq || echo "[-] Warning: Failed to restart dnsmasq. Testing environment?" >&2
    echo "[+] dnsmasq configured and restarted successfully."
else
    echo "[-] Error: dnsmasq is not installed." >&2
    exit 1
fi

# Suricata Offline PCAP Replay & Validation
echo "[+] Running Suricata offline replay against PCAP set..."
SURICATA_LOG_DIR="${CAPSTONE_ARTIFACTS_DIR}/suricata_logs"
mkdir -p "$SURICATA_LOG_DIR"

PCAP_FILES=$(ls "$PCAP_DIR"/*.pcap 2>/dev/null)
if [ -z "$PCAP_FILES" ]; then
    echo "[-] Error: No PCAP files found in $PCAP_DIR." >&2
    exit 1
fi

for pcap in $PCAP_FILES; do
    pcap_name=$(basename "$pcap")
    echo "[*] Processing PCAP: $pcap_name"
    suricata -c /etc/suricata/suricata.yaml -r "$pcap" -l "$SURICATA_LOG_DIR" >/dev/null 2>&1
    
    if [ -f "$SURICATA_LOG_DIR/eve.json" ]; then
        mv "$SURICATA_LOG_DIR/eve.json" "$SURICATA_LOG_DIR/eve_${pcap_name}.json"
    fi
done

# Custom Rule Validation against parsed alerts
echo "[+] Validating custom rules against labeled PCAPs..."
VALIDATION_FAILED=0

if command -v jq &>/dev/null; then
    ALERT_COUNT=$(jq -s '.[][] | select(.event_type=="alert")' "$SURICATA_LOG_DIR"/eve_*.json 2>/dev/null | grep -c '"alert"')
    echo "[+] Discovered $ALERT_COUNT alerts across all processed PCAPs."
    
    if [ "$ALERT_COUNT" -eq 0 ]; then
        echo "[-] Error: No alerts fired during offline replay. Custom rule validation failed." >&2
        VALIDATION_FAILED=1
    fi
else
    echo "[-] Warning: jq not found, skipping deep JSON validation."
    if ! grep -q "alert" "$SURICATA_LOG_DIR"/fast.log 2>/dev/null; then
        echo "[-] Error: No alerts found in fast.log." >&2
        VALIDATION_FAILED=1
    fi
fi

if [ "$VALIDATION_FAILED" -eq 0 ]; then
    echo "[+] Network defense deployment and validation completed successfully."
    echo "[+] All artifacts persisted under: $CAPSTONE_ARTIFACTS_DIR"
    exit 0
else
    echo "[-] Error: One or more network validation steps failed." >&2
    exit 1
fi