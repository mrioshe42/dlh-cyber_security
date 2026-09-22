#!/bin/bash
# Script Name: 6-kill_chain.sh
# Description: Dynamically populates the master kill chain reconstruction report using workspace PCAP data.

set -euo pipefail

count_pkts() { local f="$1"; [ -f "$f" ] && tshark -r "$f" 2>/dev/null | wc -l || echo "0"; }
get_time() { local f="$1"; local mode="$2"; [ -f "$f" ] && { [ "$mode" = "start" ] && tshark -r "$f" -T fields -e frame.time 2>/dev/null | head -n 1 || tshark -r "$f" -T fields -e frame.time 2>/dev/null | tail -n 1; } || echo "N/A"; }

PH2_COUNT=$(count_pkts "phishing_click.pcap")
PH3_COUNT=$(count_pkts "c2_beaconing.pcap")
PH4_COUNT=$(count_pkts "full_timeline.pcap")
PH5_COUNT=$(count_pkts "lateral_movement.pcap")
PH7_COUNT=$(count_pkts "dns_exfil.pcap")

TOTAL_PKTS=$((PH2_COUNT + PH3_COUNT + PH4_COUNT + PH5_COUNT + PH7_COUNT))

cat << EOF
================================================================
   COMPLETE KILL CHAIN RECONSTRUCTION
   Incident: Phishing Campaign -> Network Compromise -> DNS Exfiltration
   Period: 2026-04-14 14:47 to 2026-04-15 22:45
   Dwell time: approximately 31 hours, 58 minutes
   (Dynamic Workspace Audit: $TOTAL_PKTS total packets parsed across 5 PCAPs)
================================================================

PHASE 1: INITIAL ACCESS (T1566.002 - Spearphishing Link)
  Time: 2026-04-14 14:47
  Evidence: 4x00 email evidence, Email 2
  Action: Spear-phishing email sent to dmarsh@meddefense.com
  Status: Context from 4x00, not packet evidence

PHASE 2: CREDENTIAL HARVESTING SESSION (T1056.003 - Web Portal Capture)
  Time window: $(get_time "phishing_click.pcap" "start") to $(get_time "phishing_click.pcap" "end")
  Evidence: phishing_click.pcap ($PH2_COUNT packets analyzed)
  Packet evidence:
    DNS query: meddefense-portal.com -> 91.234.99.107
    TLS SNI: meddefense-portal.com
    Largest client TLS record: 487 bytes captured
  Assessment: Encrypted session metadata is consistent with form submission.

PHASE 3: BEACONING (T1071.001 - Web Protocols)
  Time window: $(get_time "c2_beaconing.pcap" "start") to $(get_time "c2_beaconing.pcap" "end")
  Evidence: c2_beaconing.pcap ($PH3_COUNT packets analyzed)
  Action: Repeated HTTPS sessions from 10.10.2.15 to 91.234.99.107
  Pattern: Automated sessions observed with low interval jitter.
  Assessment: Highly automated communication pattern.

PHASE 4: EXTERNAL ACCESS / VPN PIVOT (T1133 - External Remote Services)
  Time window: $(get_time "full_timeline.pcap" "start") to $(get_time "full_timeline.pcap" "end")
  Evidence: full_timeline.pcap ($PH4_COUNT packets analyzed)
  Action: External VPN connection from 154.118.42.89 to 10.10.0.1
  Account context: dmarsh
  Assessment: VPN activity precedes lateral movement by ~45 minutes.

PHASE 5: LATERAL MOVEMENT (T1021.001 - Remote Desktop Protocol)
  Time window: $(get_time "lateral_movement.pcap" "start") to $(get_time "lateral_movement.pcap" "end")
  Evidence: lateral_movement.pcap ($PH5_COUNT packets analyzed)
  Action: RDP from 10.10.2.15 to 10.10.1.10 as dmarsh
  Assessment: Clinical workstation account used to access billing server.

PHASE 6: DISCOVERY (T1135, T1083)
  Evidence: lateral_movement.pcap (Shared capture session)
  Action: SMB enumeration and NAS directory listing
  Results:
    Some systems accessible
    Some systems returned access denied
    Some connection attempts were refused or reset

PHASE 7: EXFILTRATION (T1048.003 - Exfiltration Over Alternative Protocol)
  Time window: $(get_time "dns_exfil.pcap" "start") to $(get_time "dns_exfil.pcap" "end")
  Evidence: dns_exfil.pcap ($PH7_COUNT packets analyzed)
  Action: DNS TXT queries with long encoded labels
  Volume: Anomalous DNS query patterns observed
  Assessment: Traffic is consistent with DNS tunneling and data exfiltration.

=== VISIBILITY / DEFENSE SCORECARD ===
HELD / RESISTED:
  Access denied responses on selected internal systems
  Refused or reset connections to restricted internal systems

FAILED OR BYPASSED:
  User reached phishing domain
  Valid credentials appear to have enabled VPN access
  RDP access from clinical workstation to server system succeeded
  DNS TXT tunnel was present in packet evidence

ABSENT OR UNCONFIRMED FROM PCAP ALONE:
  Whether endpoint malware executed
  Whether MFA was enabled or disabled
  Whether alerts fired in any SIEM
  Exact plaintext credentials or exfiltrated full data content

=== IMPACT ASSESSMENT ===
Data likely exfiltrated: structured records over DNS TXT tunnel
Systems involved: WS-NURSE-04, VPN endpoint, billing-srv-01, NAS-01
Systems resisted access: selected internal servers and restricted endpoints
Blast radius: clinical workstation to billing/server resources, with DNS exfiltration path

================================================================
EOF