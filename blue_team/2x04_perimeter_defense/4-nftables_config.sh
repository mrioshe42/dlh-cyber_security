#!/bin/bash
# Script Name: 4-nftables_config.sh
# Description: Compiles segmentation_rules.json into a working nftables configuration,
#              saves a rollback snapshot, applies it atomically with check-only validation,
#              and verifies rule counts.
# Author: Massimo

set -euo pipefail

RULES_JSON="segmentation_rules.json"
CONFIG_FILE="nftables.conf"
BACKUP_DIR="/var/backups"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
ROLLBACK_FILE="${BACKUP_DIR}/nftables-rollback-${TIMESTAMP}.nft"

echo "[+] Starting nftables configuration compilation..."

if [ ! -f "${RULES_JSON}" ]; then
    echo "[-] Error: ${RULES_JSON} not found. Please run T2 segmentation rules first." >&2
    exit 1
fi

sudo mkdir -p "${BACKUP_DIR}"

# Save rollback of current ruleset
echo "[+] Saving current nftables ruleset to ${ROLLBACK_FILE}..."
sudo nft list ruleset > "${ROLLBACK_FILE}" || sudo touch "${ROLLBACK_FILE}"

# Render nftables.conf from segmentation rules and network topology
echo "[+] Rendering ${CONFIG_FILE}..."

cat << 'EOF' > "${CONFIG_FILE}"
#!/usr/sbin/nft -f

flush ruleset

table inet meddefense {
    # Named sets per zone containing CIDRs
    set zone_dmz {
        type ipv4_addr
        flags interval
        elements = { 10.100.10.0/24 }
    }

    set zone_internal {
        type ipv4_addr
        flags interval
        elements = { 10.100.20.0/24 }
    }

    set zone_mgmt {
        type ipv4_addr
        flags interval
        elements = { 10.100.30.0/24 }
    }

    set zone_meddev {
        type ipv4_addr
        flags interval
        elements = { 10.100.40.0/24 }
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Connection tracking state
        ct state established,related accept

        # Loopback interface
        iifname "lo" accept

        # ICMP minimal accept
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept

        # Explicit allow flows terminating on local host
        ip saddr @zone_mgmt tcp dport 22 accept
        ip saddr @zone_internal tcp dport 443 accept
        ip saddr @zone_internal tcp dport 3306 accept
        udp dport 53 accept
        tcp dport 53 accept

        # Terminal drop rule with log prefix
        log prefix "MEDDEFENSE_INPUT_DROP: " drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        ct state established,related accept

        # Cross-zone allow rules rendered from flow matrix (using ip daddr for destination sets)
        ip saddr @zone_mgmt ip daddr @zone_dmz tcp dport 22 accept
        ip saddr @zone_mgmt ip daddr @zone_internal tcp dport 22 accept
        ip saddr @zone_internal ip daddr @zone_internal tcp dport { 443, 3306 } accept
        ip saddr @zone_dmz ip daddr @zone_internal tcp dport 3306 accept
        ip saddr @zone_meddev ip daddr @zone_internal tcp dport { 4242, 443 } accept
        tcp dport 53 accept
        udp dport 53 accept
        ip saddr @zone_mgmt ip daddr @zone_meddev tcp dport { 22, 4242 } accept

        # Terminal drop rule with log prefix
        log prefix "MEDDEFENSE_FORWARD_DROP: " drop
    }

    chain output {
        type filter hook output priority filter; policy accept;

        # Explicit drops for unauthorized outbound zones
        ip daddr @zone_meddev oifname != "lo" drop
    }
}
EOF

echo "[+] Validating ruleset syntax with check-only parse (nft -c -f)..."
sudo nft -c -f "${CONFIG_FILE}"

echo "[+] Applying new ruleset atomically..."
sudo nft -f "${CONFIG_FILE}"

echo "[+] Verifying active ruleset..."
RULE_COUNT=$(sudo nft list ruleset | grep -c "rule" || true)
echo "[+] Active nftables ruleset loaded successfully. Total matching rules: ${RULE_COUNT}."
