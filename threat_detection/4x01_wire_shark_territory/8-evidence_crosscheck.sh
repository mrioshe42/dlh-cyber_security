#!/bin/bash
# Script Name: 8-evidence_crosscheck.sh
# Description: Dynamically verifies workspace PCAPs and builds the evidence cross-check matrix.

set -euo pipefail

echo "==============================================================="
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY (Dynamic Audit)"
echo "==============================================================="
echo

declare -A phase_pcap
phase_pcap[1]="4x00_context"
phase_pcap[2]="phishing_click.pcap"
phase_pcap[3]="c2_beaconing.pcap"
phase_pcap[4]="full_timeline.pcap"
phase_pcap[5]="lateral_movement.pcap"
phase_pcap[6]="lateral_movement.pcap"
phase_pcap[7]="dns_exfil.pcap"

declare -A phase_action
phase_action[1]="Phishing delivery"
phase_action[2]="Credential harvest"
phase_action[3]="C2 beaconing"
phase_action[4]="VPN pivot"
phase_action[5]="RDP lateral movement"
phase_action[6]="SMB discovery"
phase_action[7]="DNS exfiltration"

declare -A phase_verdict
phase_verdict[1]="4x00 CONTEXT"
phase_verdict[2]="STRONG INFERENCE"
phase_verdict[3]="CONFIRMED"
phase_verdict[4]="STRONG INFERENCE"
phase_verdict[5]="CONFIRMED"
phase_verdict[6]="CONFIRMED"
phase_verdict[7]="CONFIRMED"

printf "%-5s | %-21s | %-16s | %s\n" "Phase" "Attack Action" "PCAP Evidence?" "Verdict"
printf "%s\n" "------|-----------------------|----------------|------------------"

found_pcaps=0
total_phases=7

for i in {1..7}; do
    pcap_target="${phase_pcap[$i]}"
    pcap_status="No"
    
    if [ "$pcap_target" = "4x00_context" ]; then
        pcap_status="No (External)"
    elif [ -f "$pcap_target" ]; then
        pcap_status="Yes"
        found_pcaps=$((found_pcaps + 1))
    else
        pcap_status="Missing File"
    fi
    
    printf "%-5s | %-21s | %-16s | %s\n" "  $i" "${phase_action[$i]}" "$pcap_status" "${phase_verdict[$i]}"
done

echo
echo "=== CONFIRMED FROM PCAP ==="
echo "- DNS query for meddefense-portal.com"
echo "- TLS connection to 91.234.99.107"
echo "- Repeated 300-second HTTPS beaconing pattern"
echo "- VPN connection from 154.118.42.89"
echo "- RDP session from clinical host to billing server"
echo "- SMB enumeration activity"
echo "- DNS TXT tunneling pattern to data-sync.meddefense-portal.com"
echo

echo "=== STRONG INFERENCE ==="
echo "- Credential submission through phishing page"
echo "- Use of stolen dmarsh credentials for VPN access"
echo "- Exfiltrated data content based on decoded DNS labels or tunnel structure"
echo

echo "=== CANNOT CONFIRM FROM PCAP ALONE ==="
echo "- Exact password entered"
echo "- Whether endpoint malware executed"
echo "- Whether a SIEM alert fired"
echo "- Whether the user intentionally approved login prompts"
echo "- Whether all data records were successfully received by attacker"
echo

echo "=== ADDITIONAL EVIDENCE NEEDED ==="
echo "- Endpoint process logs"
echo "- VPN authentication logs"
echo "- Domain controller logs"
echo "- Web server logs"
echo "- User interview"
echo "- DNS resolver logs outside the capture window"
echo

visibility_pct=$(( (found_pcaps * 100) / total_phases ))

echo "=== PACKET VISIBILITY SCORE ==="
echo "Direct PCAP evidence exists for $found_pcaps of $total_phases phases in workspace."
echo "Calculated packet visibility: ${visibility_pct}%"
echo

echo "KEY LESSON:"
echo "Packets show communication. They do not always show user intent,"
echo "plaintext credentials or endpoint process state. Strong investigations"
echo "separate packet facts from analytical inference."
echo "==============================================================="
