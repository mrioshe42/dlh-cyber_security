#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/reference" ] || D="$D/4x04"
R="$D/reference"; ADV="$R/hc3_advisory_004.txt"; MAP="$R/4x03_attack_mapping.json"
command -v jq >/dev/null && [ -r "$ADV" ] && [ -r "$MAP" ] || { echo "missing jq or reference files" >&2; exit 1; }

TTPS=(
 "T1021.002|PsExec|SMB/Windows Admin Shares|PsExec|PsExec for remote command execution on servers"
 "T1047|wmic|WMI|WMI|WMI for remote process creation and enumeration"
 "T1021.006|PSRemoting|Windows Remote Management|PSRemoting|PowerShell Remoting for interactive access and staging"
 "T1003.001|LSASS|LSASS Memory|LSASS|Credential dumping via LSASS memory access"
 "T1078.002|service account|Domain Accounts|Domain Accounts|Service account abuse for lateral authentication"
)
state() { jq -r --arg id "$1" '.techniques[]|select(.techniqueID==$id)|.comment|
          if startswith("OBSERVED") then "OBSERVED" elif startswith("INFERRED") then "INFERRED"
          elif startswith("NOT COVERED") then "NOT COVERED" else "UNKNOWN" end' "$MAP"; }

echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: $(grep -m1 -oE 'TLP:[A-Z]+' "$ADV")"
echo "================================================================"
echo; echo "HC3 ADVISORY SUMMARY:"; echo "  Stage 4 TTPs:"
for t in "${TTPS[@]}"; do IFS='|' read -r _ kw _ _ s <<<"$t"; grep -qi -- "$kw" "$ADV" && echo "    [*] $s"; done
grep -q "01:00" "$ADV" && echo "    [*] Off-hours operations to avoid detection"

echo; echo "ATT&CK COVERAGE GAP ANALYSIS:"
jq -r '.technique_count_summary|"  Current coverage: \(.observed)/\(.total_in_threat_model) techniques (\(.percent_observed)%)"' "$MAP"
echo "  Lateral movement / credential access by state:"
for s in OBSERVED INFERRED "NOT COVERED"; do
  printf "    %-12s %s\n" "$s:" "$(jq -r --arg s "$s" '[.techniques[]|select(.tactic=="lateral-movement" or .tactic=="credential-access")
    |select(.comment|startswith($s))|.techniqueID]|if length>0 then join(", ") else "none" end' "$MAP")"
done
echo "  Stage 4 techniques in gap:"
GAP=()
for t in "${TTPS[@]}"; do IFS='|' read -r id _ name label _ <<<"$t"
  [ "$(state "$id")" = "NOT COVERED" ] && { GAP+=("$id|$label"); printf "    %-10s %-28s NOT COVERED\n" "$id" "$name"; }
done

echo; echo "HUNT PRIORITY RANKING:"
n=0; for id in T1021.002 T1003.001 T1047 T1021.006 T1078.002; do
  for g in "${GAP[@]}"; do [ "${g%%|*}" = "$id" ] && echo "  P$((++n)): $id ${g#*|}"; done
done

cat <<'EOF'

DATA SOURCES:
  Primary:   siem_export/wazuh_alerts_14d.json
  Secondary: siem_export/wazuh_raw_sysmon_14d.json
  Baseline:  baseline/robert_kim_activity.json
  Reference: admin_schedule.txt, service_accounts.txt

TIME WINDOW: 14 days

================================================================
EOF
