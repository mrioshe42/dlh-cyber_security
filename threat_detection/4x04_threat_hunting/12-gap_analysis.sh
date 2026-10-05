#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
B="$D/baseline/robert_kim_activity.json"; SCHED="$D/reference/admin_schedule.txt"

BHOST=$(jq -rs 'map(.hunt_meta.source_host) | unique | join(",")' "$B")
BUSER=$(jq -rs 'map(.data.win.eventdata.user) | unique | join(",")' "$B")
read -r H0 H1 < <(grep -m1 "Work hours:" "$SCHED" | grep -oE '[0-9]{2}:00' | head -2 | tr -d ':0' | paste -sd' ')
H0=$((10#${H0:-8})); H1=$((10#${H1:-18}))

jq -rs --arg bh "$BHOST" --arg bu "$BUSER" --argjson h0 "$H0" --argjson h1 "$H1" '
  unique_by(.id) | sort_by(.timestamp) | map(.data.win.eventdata as $d | {
      id, ts: .timestamp, host: .agent.name, rule: .rule.id, level: .rule.level, eid: .data.win.system.eventID,
      user: (($d.user // $d.sourceUser // "") | split("\\") | (last // "")), cmd: ($d.commandLine // ""),
      img: (($d.image // "") + " " + ($d.commandLine // "")), parent: ($d.parentImage // ""), src: ($d.sourceImage // ""),
      tgt: ($d.targetImage // ""), mask: ($d.grantedAccess // ""), acct: (($d.targetUserName // "") | ascii_downcase),
      ws: ($d.workstationName // ""), pkg: ($d.authenticationPackageName // ""),
      hour: ((.timestamp[0:19] + "Z" | fromdateiso8601 - 18000) | strftime("%H") | tonumber)}) as $all
  | [ ["T1021.002 PsExec Lateral Movement", ($all | map(select((.img | test("psexec"; "i")) and .host != "WS-ADMIN-01"))), ["1"],
       "Image/CommandLine=psexec*; alert if host not in {\($bh)}, user not in {\($bu)}, or outside \($h0):00-\($h1):00 Central"],
      ["T1003.001 LSASS Credential Access", ($all | map(select(.rule == "61640" and (.tgt | test("lsass")) and (.src | test("System32") | not)))), ["10"],
       "TargetImage=lsass.exe with GrantedAccess 0x10; allowlist SourceImage in {\($all | map(select(.rule == "61640" and (.src | test("System32"))) | .src | split("\\") | last) | unique | join(","))}"],
      ["T1078.002 Service Account Misuse", ($all | map(select(.eid == "4624" and (.acct | test("^svc_")) and (.ws | test("^WS-"))))), ["4624"],
       "TargetUserName ^svc_; alert if WorkstationName ^WS- or not the account'"'"'s authorized host in service_accounts.txt"],
      ["T1047 WMI Remote Execution", ($all | map(select((.parent | test("WmiPrvSE")) and (.user | test("^svc_"))))), ["1"],
       "ParentImage=WmiPrvSE.exe; baseline WMI only from {\($bh)} as {\($bu)}; alert on service-account users"],
      ["T1021.006 PowerShell Remoting", ($all | map(select(((.parent | test("wsmprovhost")) or (.img | test("Enter-PSSession"))) and .host != "WS-ADMIN-01"))), ["1", "4104"],
       "ParentImage=wsmprovhost.exe or Enter-PSSession; baseline only from {\($bh)}; enable 4103/4104 script-block logging"],
      ["T1550.002 NTLM / Pass-the-Hash-style Activity", ($all | map(select(.eid == "4624" and .pkg == "NTLM"))), ["4624"],
       "AuthenticationPackageName=NTLM for ^svc_ accounts (service accounts must use Kerberos)"]]
  | map(select(.[1] | length > 0) | . as [$name, $m, $need, $rule]
      | {name: $name, rule: $rule, ids: ($m | map(.id)), first: $m[0].ts, level: ($m | map(.level) | max),
         reached: ($m | map(if .eid == "4624" then .host else ((.cmd | [scan("SRV-[A-Za-z0-9-]+")] | first) // .host) end) | unique),
         find: "\($m | length) events from \($m | map(.host) | unique | join(", ")) as \($m | map(.user, .acct) | map(select(. != "")) | unique | join(", ")); \($m | map(select(.hour < $h0 or .hour >= $h1)) | length) outside business hours",
         rules: ($m | map("\(.rule) L\(.level)") | unique | join(", ")),
         src: ($m | map("\(if .eid | IN("1","3","10") then "Sysmon Event" else "Windows Event" end) \(.eid)") | unique | join(", ")),
         lacking: ($need | map(select(. as $n | $all | map(.eid) | index($n) | not)))})
  | (map(.first) | min) as $t0
  | reduce .[] as $g ([]; . as $p | . + [$g + {dup: ($p | map(select(.ids as $x | $g.ids | all(. as $i | $x | index([$i])))) | map(.name[0:9]) | first),
        prio: (if $g.first == $t0 or ($g.reached | any(test("DC"))) then "P1" elif ($g.reached | any(test("DB"))) then "P2" else "P3" end)}])
  | map(if .dup then .prio = "P3" else . end) | sort_by(.prio, .first) | to_entries[] | .key as $i | .value as $g
  | "\nGAP \($i + 1): \($g.name)",
    "  Hunt Finding:  \($g.find); reached \($g.reached | join(", "))",
    "  Why Missed:    \(if ($g.lacking | length) > 0 then "Missing data (no event \($g.lacking | join("/"))); " else "" end)Missing rule - data existed but only generic rule(s) \($g.rules) fired",
    "  Data Source:   \($g.src)\(if ($g.lacking | length) > 0 then " + PowerShell logs (missing)" else "" end)",
    "  Required Rule: \($g.rule)",
    "  Priority:      \($g.prio)\(if $g.dup then " (same events as \($g.dup); closed by that rule)" else "" end)"' \
  "$D/siem_export/wazuh_alerts_14d.json" "$D/siem_export/wazuh_raw_sysmon_14d.json" \
  | { echo "================================================================"; echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"; echo "================================================================"; cat
      echo; echo "SUMMARY:"; echo "  The data was present."; echo "  The detection logic was missing."; echo "  Proactive hunting exposed the gap."
      echo; echo "================================================================"; }
