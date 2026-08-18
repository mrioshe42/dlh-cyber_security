#!/bin/bash
# Script Name: 0-network_baseline.sh
# Description: Discovers local network topology from the hardened endpoint's 
#              perspective and outputs a structured JSON baseline artifact, MAC addresses, IP addresses, routing tables, listening sockets, and DNS resolver configuration.
#              link state
# Author: Massimo

set -euo pipefail

OUTPUT_FILE="network_baseline.json"
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[+] Starting network baseline collection on ${HOSTNAME_VAL} at ${TIMESTAMP}..."

# Verify required binary dependencies
for cmd in ip ss jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "[-] Error: Required command '${cmd}' is not installed." >&2
        exit 1
    fi
done

INTERFACES=$(ip -j addr show)
ROUTES=$(ip -j route show)
NEIGHBORS=$(ip -j neigh show)

# Enumerate listening TCP and UDP sockets with ss
if ss -j -tulnpH &>/dev/null; then
    LISTENERS_JSON=$(ss -j -tulnpH)
else
    LISTENERS_JSON=$(ss -tulnpH | awk '{print "{\"state\": \"" $1 "\", \"recv_q\": " $2 ", \"send_q\": " $3 ", \"local_address\": \"" $4 "\", \"peer_address\": \"" $5 "\", \"process\": \"" $6 "\"}"}' | jq -s . 2>/dev/null || echo "[]")
fi

# Enumerate established outbound connections with ss
if ss -j -tnpH state established &>/dev/null; then
    ESTABLISHED_JSON=$(ss -j -tnpH state established)
else
    ESTABLISHED_JSON=$(ss -tnpH state established | awk '{print "{\"state\": \"" $1 "\", \"local_address\": \"" $4 "\", \"peer_address\": \"" $5 "\", \"process\": \"" $6 "\"}"}' | jq -s . 2>/dev/null || echo "[]")
fi

# Capture DNS resolver configuration
RESOLV_CONF=""
if [ -f /etc/resolv.conf ]; then
    RESOLV_CONF=$(cat /etc/resolv.conf | jq -Rs .)
else
    RESOLV_CONF="\"/etc/resolv.conf not found\""
fi

RESOLVED_STATUS="{}"
if command -v resolvectl &>/dev/null; then
    RESOLVED_STATUS=$(resolvectl status --no-pager | jq -Rs . 2>/dev/null || echo "\"systemd-resolved status unavailable\"")
fi

jq -n \
    --arg ts "${TIMESTAMP}" \
    --arg host "${HOSTNAME_VAL}" \
    --argjson ifaces "${INTERFACES}" \
    --argjson routes "${ROUTES}" \
    --argjson neigh "${NEIGHBORS}" \
    --argjson listeners "${LISTENERS_JSON}" \
    --argjson established "${ESTABLISHED_JSON}" \
    --argjson resolv_conf "${RESOLV_CONF}" \
    --argjson resolved_status "${RESOLVED_STATUS}" \
    '{
        timestamp: $ts,
        hostname: $host,
        interfaces: $ifaces,
        routes: $routes,
        neighbors: $neigh,
        listening_sockets: $listeners,
        established_connections: $established,
        dns_resolvers: {
            resolv_conf: $resolv_conf,
            systemd_resolved: $resolved_status
        }
    }' > "${OUTPUT_FILE}"

echo "[+] Baseline successfully captured and written to ${OUTPUT_FILE}."
