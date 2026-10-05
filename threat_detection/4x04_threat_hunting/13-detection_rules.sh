#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
OUT="$(dirname "$(readlink -f "$0")")/detection_rules"; mkdir -p "$OUT"
BASE="$D/baseline/robert_kim_activity.json"; MAP="$D/reference/4x03_attack_mapping.json"
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
AH=$(jq -rs '.[0].agent.name' "$BASE"); AIP=$(jq -rs '.[0].agent.ip' "$BASE")

STATS=$(jq -rs --slurpfile b "$BASE" --arg ah "$AH" '
  def norm: unique_by(.id) | map(.data.win.eventdata as $d | {host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
      img: (($d.image // "") + " " + ($d.commandLine // "")), parent: ($d.parentImage // ""), src: ($d.sourceImage // ""),
      tgt: ($d.targetImage // ""), acct: ($d.targetUserName // ""), ws: ($d.workstationName // ""), port: ($d.destinationPort // "")});
  def fires($k): if $k == 1 then (.img | test("psexec"; "i")) and .host != $ah
    elif $k == 2 then .rule == "61640" and (.tgt | test("lsass")) and (.src | test("System32") | not)
    elif $k == 3 then .eid == "4624" and (.acct | test("^svc_")) and (.ws | test("^WS-"))
    elif $k == 4 then (.parent | test("WmiPrvSE"))
    else .eid == "3" and .port == "445" and (.img | test("psexec"; "i")) and .host != $ah end;
  def inspects($k): if $k == 1 or $k == 5 then (.img | test("psexec"; "i")) elif $k == 2 then .rule == "61640"
    elif $k == 3 then .eid == "4624" and (.acct | test("^svc_")) elif $k == 4 then (.parent | test("WmiPrvSE")) else false end;
  norm as $a | ($b | norm) as $base | range(1; 6) as $k
  | "\($k)|\($a | map(select(fires($k))) | length)|\($base | map(select(fires($k))) | length)|\($a | map(select(inspects($k) and (fires($k) | not))) | length)|\($base | map(select(if $k == 4 then .img | test("wmic"; "i") else inspects($k) end)) | length)"' \
  "$D/siem_export/wazuh_alerts_14d.json" "$D/siem_export/wazuh_raw_sysmon_14d.json")

fp() { IFS='|' read -r _ _ hit pop tool < <(sed -n "$1p" <<<"$STATS")
       if [ "$hit" -gt 0 ]; then echo HIGH; elif [ "$1" = 4 ] && [ "$tool" -gt 0 ]; then echo MEDIUM; elif [ "$pop" -ge 40 ]; then echo "VERY LOW"; else echo LOW; fi; }
hits() { sed -n "$1p" <<<"$STATS" | cut -d'|' -f2; }

echo "================================================================"
echo "   DETECTION ENGINEERING - Hunt-Derived Rules"
echo "================================================================"
while IFS='|' read -r i id name behavior task logic; do
  [ "$i" = 1 ] && printf '\n=== WAZUH-STYLE RULE DRAFTS ===\n'; [ "$i" = 5 ] && printf '\n=== NETWORK RULE DRAFTS ===\n'
  printf '\n[Rule %s] %s\n  Behavior: %s\n  Evidence: Hunt %s - fires on %s events in the 14-day data\n  Baseline: %s\n  FP Rate:  %s\n' \
         "$id" "$name" "$behavior" "$task" "$(hits "$i")" "$logic" "$(fp "$i")"
done <<EOT
1|100100|PsExec from Non-Admin Workstation|PsExec execution from a host other than $AH|Task 4|alert if host != $AH (only admin source in baseline) or outside 08:00-18:00
2|100101|LSASS Memory Access from Non-System Process|lsass.exe opened by a process outside the System32 allowlist|Task 6|allowlist csrss/services/svchost/wininit/WmiPrvSE; alert on any other SourceImage
3|100102|Service Account Interactive Logon from Workstation|svc_* account logon with WorkstationName WS-*|Task 9|svc_* logs on only from its service host (0 workstation logons)
4|100103|WMI Remote Child Process Anomaly|wmiprvse.exe spawning cmd.exe or powershell.exe|Task 5|admin WMI inventory runs from $AH as robert.kim; alert on any other user/source
5|9000030|SMB Lateral Movement - PsExec Service Installation|PSEXESVC service-install pattern over SMB (445)|Task 4|exclude $AIP (admin workstation); alert on all other sources
EOT

cat > "$OUT/hunt_rules.xml" <<XML
<group name="healthbane,hunt_derived,">
  <rule id="100100" level="12"><if_sid>61603</if_sid><field name="win.eventdata.image" type="pcre2">(?i)psexec</field><field name="agent.name" negate="yes">$AH</field>
    <description>PsExec from non-admin workstation</description><mitre><id>T1021.002</id></mitre></rule>
  <rule id="100101" level="13"><if_sid>61640</if_sid><field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe\$</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)^C:\\\\Windows\\\\System32\\\\</field>
    <description>LSASS memory access from non-system process</description><mitre><id>T1003.001</id></mitre></rule>
  <rule id="100102" level="12"><if_sid>60106</if_sid><field name="win.eventdata.targetUserName" type="pcre2">^svc_</field><field name="win.eventdata.workstationName" type="pcre2">^WS-</field>
    <description>Service account logon from workstation</description><mitre><id>T1078.002</id></mitre></rule>
  <rule id="100103" level="10"><if_sid>61603</if_sid><field name="win.eventdata.parentImage" type="pcre2">(?i)wmiprvse\.exe\$</field><field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell)\.exe\$</field>
    <description>WMI remote child process anomaly</description><mitre><id>T1047</id></mitre></rule>
</group>
XML
echo "alert tcp !$AIP any -> \$HOME_NET 445 (msg:\"HUNT SMB lateral movement - PsExec service installation\"; flow:to_server,established; content:\"PSEXESVC\"; nocase; sid:9000030; rev:1;)" > "$OUT/network.rules"

read -r TOTAL OBS < <(jq -r '.technique_count_summary | "\(.total_in_threat_model) \(.observed)"' "$MAP")
NEW=$(jq -n --slurpfile m "$MAP" '["T1021.002","T1003.001","T1078.002","T1047"] | map(. as $t | select($m[0].techniques | any(.techniqueID == $t and (.comment | startswith("OBSERVED") | not)))) | length')
printf '\n=== DETECTION POSTURE UPDATE ===\n  Before hunt: %s%% observed coverage (%s/%s)\n  After hunt:  %s%% coverage (%s/%s, +%s techniques with new rules)\n  Rule drafts: %s/\n\n' \
       $((OBS * 100 / TOTAL)) "$OBS" "$TOTAL" $(((OBS + NEW) * 100 / TOTAL)) $((OBS + NEW)) "$TOTAL" "$NEW" "$OUT"
echo "================================================================"
