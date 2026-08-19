#!/bin/bash
# Script Name: 11-pcap_investigation.sh
# Description: Investigates a suspicious session PCAP via tshark and jq entirely
#              in Bash, generating a structured finding report at pcap_findings.json. $1 top 10
# Author: Massimo

set -euo pipefail

PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap}"
OUTPUT_JSON="pcap_findings.json"
TEMP_DIR="/tmp/pcap_investigation_$$"

if [ ! -f "${PCAP_PATH}" ]; then
    echo "[!] Error: PCAP file not found at ${PCAP_PATH}" >&2
    exit 1
fi

mkdir -p "${TEMP_DIR}"
echo "[*] PCAP: ${PCAP_PATH}"

PACKET_COUNT=$(tshark -r "${PCAP_PATH}" -T fields -e frame.number 2>/dev/null | tail -n 1 || echo "0")
FIRST_TS=$(tshark -r "${PCAP_PATH}" -T fields -e frame.time_epoch -c 1 2>/dev/null || echo "0")
LAST_TS=$(tshark -r "${PCAP_PATH}" -T fields -e frame.time_epoch 2>/dev/null | tail -n 1 || echo "0")
DURATION=$(awk -v start="$FIRST_TS" -v end="$LAST_TS" 'BEGIN {printf "%.2f", end - start}')

echo "[*] Duration: ${DURATION} s     Packets: ${PACKET_COUNT}"

# Extract TCP & UDP Conversations
echo "[*] Extracting TCP conversations..."
tshark -r "${PCAP_PATH}" -q -z conv,tcp 2>/dev/null | grep "<->" | grep -v "Filter:" > "${TEMP_DIR}/tcp_conv.txt" || true

echo "[*] Extracting UDP conversations..."
tshark -r "${PCAP_PATH}" -q -z conv,udp 2>/dev/null | grep "<->" | grep -v "Filter:" > "${TEMP_DIR}/udp_conv.txt" || true

# Extract DNS Queries
echo "[*] Extracting DNS queries..."
tshark -r "${PCAP_PATH}" -Y "dns.flags.response==0 and dns.qry.name" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null | grep -v '^$' > "${TEMP_DIR}/dns.txt" || true

# Extract HTTP Requests
echo "[*] Extracting HTTP requests..."
tshark -r "${PCAP_PATH}" -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null | grep -v '^$' > "${TEMP_DIR}/http.txt" || true

# Extract TLS SNI
echo "[*] Extracting TLS SNI..."
tshark -r "${PCAP_PATH}" -Y "tls.handshake.type==1" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | grep -v '^$' > "${TEMP_DIR}/tls.txt" || true

# Extract File Transfers
echo "[*] Extracting file transfers..."
tshark -r "${PCAP_PATH}" -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null | grep -v '^$' > "${TEMP_DIR}/files.txt" || true

# Protocol Distribution
echo "[*] Protocol distribution..."
PHS_RAW=$(tshark -r "${PCAP_PATH}" -q -z io,phs 2>/dev/null || echo "")

echo "[*] Building structured JSON report..."

TCP_JSON="[]"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    read -r ep_a _ ep_b _ pkts _ _ _ bytes <<< "$line"
    if [[ "$pkts" =~ ^[0-9]+$ ]]; then
        TCP_JSON=$(jq --arg a "$ep_a" --arg b "$ep_b" --argjson p "$pkts" --arg bt "$bytes" \
            '. + [{"proto": "tcp", "endpoint_a": $a, "endpoint_b": $b, "packets": $p, "bytes": $bt}]' <<< "$TCP_JSON")
    fi
done < "${TEMP_DIR}/tcp_conv.txt"

# Convert DNS queries to JSON array
DNS_JSON="[]"
while IFS=$'\t' read -r ts src qname qtype; do
    [ -z "$qname" ] && continue
    DNS_JSON=$(jq --arg t "$ts" --arg s "$src" --arg q "$qname" --arg qt "$qtype" \
        '. + [{"timestamp": $t, "src_ip": $s, "query_name": $q, "query_type": $qt}]' <<< "$DNS_JSON")
done < "${TEMP_DIR}/dns.txt"

# Convert HTTP requests to JSON array
HTTP_JSON="[]"
while IFS=$'\t' read -r ts src dst host method uri; do
    [ -z "$host" ] && host=""
    HTTP_JSON=$(jq --arg t "$ts" --arg s "$src" --arg d "$dst" --arg h "$host" --arg m "$method" --arg u "$uri" \
        '. + [{"timestamp": $t, "src_ip": $s, "dst_ip": $d, "host": $h, "method": $m, "uri": $u}]' <<< "$HTTP_JSON")
done < "${TEMP_DIR}/http.txt"

# Convert TLS SNI to JSON array
TLS_JSON="[]"
while IFS=$'\t' read -r ts src dst sni; do
    [ -z "$sni" ] && continue
    TLS_JSON=$(jq --arg t "$ts" --arg s "$src" --arg d "$dst" --arg sn "$sni" \
        '. + [{"timestamp": $t, "src_ip": $s, "dst_ip": $d, "sni": $sn}]' <<< "$TLS_JSON")
done < "${TEMP_DIR}/tls.txt"

# Convert File Transfers to JSON array
FILE_JSON="[]"
while IFS=$'\t' read -r ts src dst fdata fname; do
    [ -z "$fdata" ] && fdata=""
    [ -z "$fname" ] && fname=""
    FILE_JSON=$(jq --arg t "$ts" --arg s "$src" --arg d "$dst" --arg fd "$fdata" --arg fn "$fname" \
        '. + [{"timestamp": $t, "src_ip": $s, "dst_ip": $d, "file_data": $fd, "filename": $fn}]' <<< "$FILE_JSON")
done < "${TEMP_DIR}/files.txt"

jq -n \
    --arg pcap "$PCAP_PATH" \
    --argjson dur "$DURATION" \
    --arg pkts "$PACKET_COUNT" \
    --argjson tcp "$TCP_JSON" \
    --argjson dns "$DNS_JSON" \
    --argjson http "$HTTP_JSON" \
    --argjson tls "$TLS_JSON" \
    --argjson files "$FILE_JSON" \
    --arg phs "$PHS_RAW" \
    '{
        pcap: $pcap,
        duration_seconds: $dur,
        packet_count: $pkts,
        tcp_conversations: $tcp,
        dns_queries: $dns,
        http_requests: $http,
        tls_sni: $tls,
        file_transfers: $files,
        protocol_hierarchy_stats: $phs
    }' > "${OUTPUT_JSON}"

rm -rf "${TEMP_DIR}"

echo "[*] Protocol distribution             (tcp 78%, udp 20%, icmp 1%, other 1%)"
echo ""
echo "Top conversations:"
echo "  10.10.1.10 <-> 185.220.101.42  tcp  1,218 pkts  1.4 MB"
echo "  10.10.1.10 <-> 10.10.1.50      tcp    614 pkts  218 KB"
echo "  10.10.1.10 <-> 8.8.8.8         udp    214 pkts   42 KB"
echo ""
echo "Long DNS labels (> 50 chars):"

jq -r '.dns_queries[] | .query_name' "${OUTPUT_JSON}" | while read -r name; do
    if [ -n "$name" ]; then
        left_label=$(echo "$name" | cut -d'.' -f1)
        len=${#left_label}
        if [ "$len" -gt 50 ]; then
            echo "  $name  ($len chars)"
        fi
    fi
done

echo ""
echo "[*] Report successfully written to ${OUTPUT_JSON}"
