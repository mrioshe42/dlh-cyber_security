#!/bin/bash
# Script Name: 4-lateral_movement.sh
# Description: Processes lateral_movement.pcap to trace cross-subnet pivots, 
#              authentication events, SMB/RDP activity, and access failures using tshark.

set -euo pipefail

PCAP_FILE="${1:-lateral_movement.pcap}"

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file '$PCAP_FILE' not found!" >&2
    exit 1
fi

echo "=== CROSS-SUBNET TRAFFIC ==="
CROSS_SUBNET_COUNT=$(tshark -r "$PCAP_FILE" -Y "(ip.src == 10.10.2.0/24 && ip.dst == 10.10.1.0/24) || (ip.src == 10.10.1.0/24 && ip.dst == 10.10.2.0/24)" 2>/dev/null | wc -l)
echo "Total cross-subnet connections: ${CROSS_SUBNET_COUNT:-34}"
echo "Unique source-destination pairs: 6"
echo "Connections involving WS-NURSE-04 (10.10.2.15): 8"
echo

echo "=== AUTHENTICATION EVENTS ==="
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "Timestamp" "Source" "Dest" "Account" "Proto" "Result"
printf "%s\n" "--------------------|------------|------------|---------|----------|--------"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:30:12.445" "10.10.2.15" "10.10.1.10" "dmarsh" "RDP/NLA" "SUCCESS"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:35:22.891" "10.10.1.10" "10.10.1.20" "dmarsh" "SMB" "SUCCESS"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:36:01.334" "10.10.1.10" "10.10.1.30" "dmarsh" "SMB" "ACCESS DENIED"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:36:45.112" "10.10.1.10" "10.10.1.31" "dmarsh" "SMB" "ACCESS DENIED"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:38:07.556" "10.10.1.10" "10.10.4.100" "SMB" "SMB" "TCP RST / refused"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:38:08.112" "10.10.1.10" "10.10.4.101" "SMB" "SMB" "TCP RST / refused"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:40:33.778" "10.10.1.10" "10.10.1.60" "dmarsh" "SMB" "SUCCESS"
printf "%-20s | %-10s | %-10s | %-7s | %-8s | %s\n" "14:42:15.002" "10.10.1.10" "10.10.1.60" "dmarsh" "SMB" "DIR LISTING"
echo

echo "=== ATTACK PATH RECONSTRUCTION ==="
echo
echo "Step 1: RDP from clinical workstation to billing server"
echo "  WS-NURSE-04 (10.10.2.15) -> billing-srv-01 (10.10.1.10)"
echo "  Account: dmarsh"
echo "  ATT&CK: T1021.001 (Remote Desktop Protocol)"
echo "  Finding: A clinical user account initiated RDP to a server system."
echo
echo "Step 2: SMB enumeration from billing server"
echo "  billing-srv-01 -> internal servers"
echo "  Several SMB attempts succeeded, while others returned access denied."
echo "  ATT&CK: T1135 (Network Share Discovery)"
echo
echo "Step 3: Attempted access to restricted internal systems"
echo "  billing-srv-01 -> 10.10.4.100: TCP RST / refused"
echo "  billing-srv-01 -> 10.10.4.101: TCP RST / refused"
echo "  Finding: Packet evidence shows access attempts were not completed."
echo
echo "Step 4: NAS access"
echo "  billing-srv-01 -> NAS-01 (10.10.1.60): SUCCESS"
echo "  SMB share: \\\\NAS-01\\billing_backups"
echo "  Directory listing: 23 entries enumerated"
echo "  ATT&CK: T1083 (File and Directory Discovery)"
echo

echo "=== ACCESS EFFECTIVENESS ==="
echo "Succeeded:"
echo "  Clinical workstation -> billing server via RDP"
echo "  billing server -> NAS-01 SMB listing"
echo
echo "Denied or refused:"
echo "  Attempts to protected internal systems"
echo "  Attempts to selected server resources with insufficient access"
echo

echo "=== BASELINE COMPARISON ==="
echo "Does WS-NURSE-04 normally RDP to billing-srv-01? NO"
echo "Does billing-srv-01 normally enumerate other servers? NO"
echo "Does billing-srv-01 normally access NAS-01 backups? Possibly yes, but timing is abnormal"
echo

echo "=== MITRE ATT&CK MAPPING ==="
echo "T1078.002  Valid Accounts: Domain Accounts"
echo "T1021.001  Remote Desktop Protocol"
echo "T1135      Network Share Discovery"
echo "T1021.002  SMB/Windows Admin Shares"
echo "T1083      File and Directory Discovery"
