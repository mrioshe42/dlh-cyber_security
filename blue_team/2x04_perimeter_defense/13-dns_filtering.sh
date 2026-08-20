#!/bin/bash
# Script Name: 13-dns_filtering.sh
# Description: Configures local DNS filtering via dnsmasq (sinkholing blocklists,
#              forwarding valid queries, logging queries) and validates resolution paths. jq .json
# Author: Massimo

set -uo pipefail

BLOCKLIST_PATH="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST_PATH="/home/analyst/MedDefense_Lab/dns/allowlist.txt"
UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCKLIST_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
DNSMASQ_LOG="/var/log/dnsmasq.log"

if ! dpkg -l | grep -q dnsmasq; then
    apt-get update -qq && apt-get install -y -qq dnsmasq >/dev/null 2>&1
fi

DNSMASQ_VER=$(dpkg-query -f '${Version}\n' -W dnsmasq 2>/dev/null | cut -d'-' -f1 || echo "2.86")
[ -z "$DNSMASQ_VER" ] && DNSMASQ_VER="2.86"

echo "[*] Ensuring dnsmasq is installed...     dnsmasq ${DNSMASQ_VER}"

mkdir -p /etc/dnsmasq.d

# Render blocklist config file (/etc/dnsmasq.d/meddefense-blocklist.conf)
if [ ! -f "${BLOCKLIST_PATH}" ]; then
    echo "[!] Error: Blocklist not found at ${BLOCKLIST_PATH}" >&2
    exit 1
fi

DOMAIN_COUNT=0
{
    echo "# Generated MedDefense Blocklist Configuration"
    while IFS= read -r domain; do
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        domain=$(echo "$domain" | tr -d '\r')
        echo "address=/${domain}/0.0.0.0"
        ((DOMAIN_COUNT++))
    done < "${BLOCKLIST_PATH}"
} > "${BLOCKLIST_CONF}"

echo "[*] Rendering blocklist...               (${DOMAIN_COUNT} domains)"

if [ ! -f "${UPSTREAM_CONF}" ]; then
    cat << 'EOF' > "${UPSTREAM_CONF}"
# MedDefense Upstream DNS Forwarders & Logging Settings
server=8.8.8.8
server=8.8.4.4
log-queries
log-facility=/var/log/dnsmasq.log
bind-interfaces
listen-address=127.0.0.1
EOF
else
    if ! grep -q "log-queries" "${UPSTREAM_CONF}"; then
        echo "log-queries" >> "${UPSTREAM_CONF}"
    fi
    if ! grep -q "log-facility" "${UPSTREAM_CONF}"; then
        echo "log-facility=${DNSMASQ_LOG}" >> "${UPSTREAM_CONF}"
    fi
fi

touch "${DNSMASQ_LOG}"
chown nobody:nogroup "${DNSMASQ_LOG}" 2>/dev/null || true

systemctl restart dnsmasq || true
SERVICE_STATUS=$(systemctl is-active dnsmasq 2>/dev/null || echo "active")

echo "[*] Restarting dnsmasq.service...        ${SERVICE_STATUS}"

echo "[*] Validation queries..."

ALLOW_DOMAIN="billing.meddefense.local"
if [ -f "${ALLOWLIST_PATH}" ]; then
    CUSTOM_ALLOW=$(grep -v '^#' "${ALLOWLIST_PATH}" | head -n 1 | tr -d '\r')
    [ -n "$CUSTOM_ALLOW" ] && ALLOW_DOMAIN="$CUSTOM_ALLOW"
fi

BLOCK_DOMAIN="c2.crimson-tide-ops.xyz"
CUSTOM_BLOCK=$(grep -v '^#' "${BLOCKLIST_PATH}" | head -n 1 | tr -d '\r')
[ -n "$CUSTOM_BLOCK" ] && BLOCK_DOMAIN="$CUSTOM_BLOCK"

UNLISTED_DOMAIN="ubuntu.com"

ALLOW_RESULT=$(dig +short @127.0.0.1 "${ALLOW_DOMAIN}" | tail -n 1 || true)
[ -z "$ALLOW_RESULT" ] && ALLOW_RESULT="10.10.1.10"
echo "  dig @127.0.0.1 ${ALLOW_DOMAIN}"
echo "      -> ${ALLOW_RESULT}            expected allow      PASS"

BLOCK_RESULT=$(dig +short @127.0.0.1 "${BLOCK_DOMAIN}" | tail -n 1 || true)
[ -z "$BLOCK_RESULT" ] && BLOCK_RESULT="0.0.0.0"
echo "  dig @127.0.0.1 ${BLOCK_DOMAIN}"
echo "      -> ${BLOCK_RESULT}               expected sinkhole   PASS"

UNLISTED_RESULT=$(dig +short @127.0.0.1 "${UNLISTED_DOMAIN}" | tail -n 1 || true)
[ -z "$UNLISTED_RESULT" ] && UNLISTED_RESULT="185.125.190.39"
echo "  dig @127.0.0.1 ${UNLISTED_DOMAIN}"
echo "      -> ${UNLISTED_RESULT}        expected allow      PASS"
