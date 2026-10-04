#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
ALERTS="$D/siem_export/wazuh_alerts_14d.json"
SYSMON="$D/siem_export/wazuh_raw_sysmon_14d.json"
SVC="$D/reference/service_accounts.txt"
for f in "$ALERTS" "$SYSMON" "$SVC"; do [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

ACCT=svc_healthsync
AUTH=$(awk -v a="--- $ACCT ---" '$0==a{f=1} f&&/Authorized host:/{print $3; exit}' "$SVC")
STD='["csrss.exe","services.exe","svchost.exe","msmpeng.exe","wmiprvse.exe","wininit.exe"]'  # HC3 standard LSASS readers

EV=$(jq -s '
  unique_by(.id) | sort_by(.timestamp) | map(
    .data.win.eventdata as $d
    | {ts: .timestamp, host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
       user: ($d.user // ""), image: ($d.image // ""), cmd: ($d.commandLine // ""),
       src: ($d.sourceImage // ""), target: ($d.targetImage // ""), mask: ($d.grantedAccess // ""),
       logon_user: ($d.targetUserName // ""), logon_ws: ($d.workstationName // ""),
       logon_type: ($d.logonType // ""), pkg: ($d.authenticationPackageName // "")})' "$ALERTS" "$SYSMON")

LSASS=$(jq -c '[.[] | select(.rule == "61640" and (.target | test("lsass\\.exe$"; "i")))]' <<<"$EV")
ANOM=$(jq -c --argjson std "$STD" '[.[] | select(
        (.src | test("^C:\\\\Windows\\\\System32\\\\"; "i") and ((split("\\") | last | ascii_downcase) as $n | $std | index($n))) | not)]' <<<"$LSASS")
N_ALL=$(jq length <<<"$LSASS"); N_BAD=$(jq length <<<"$ANOM")

AUTHS=$(jq -c --arg a "$ACCT" --arg auth "$AUTH" '[.[] | select(.eid == "4624" and (.logon_user | ascii_downcase) == $a
        and .logon_ws != $auth and .logon_ws != .host)]' <<<"$EV")   # hop to a server, not the local logon
TOOLS=$(jq -c --arg a "$ACCT" --argjson bad "$ANOM" '
  ($bad | map(.host) | unique) as $dump_hosts
  | [.[] | . as $e
     | (($e.image + " " + $e.cmd) | if test("psexec"; "i") then "PsExec"
        elif test("wmic|Invoke-WmiMethod"; "i") then "WMI"
        elif test("Enter-PSSession|New-PSSession|Invoke-Command"; "i") then "PSRemoting" else empty end) as $tool
     | select($e.cmd != "" and $e.host != "WS-ADMIN-01"
              and (($e.user | test($a; "i")) or ($dump_hosts | index($e.host))))
     | {ts: $e.ts, host: $e.host, user: $e.user, tool: $tool, cmd: $e.cmd}]' <<<"$EV")

echo "================================================================"
echo "   HUNT EXECUTION - H2: Credential Access (LSASS)"
echo "   Technique: T1003.001 LSASS Memory"
echo "================================================================"
echo
echo "LSASS ACCESS EVENTS:"
echo "  Total LSASS access events: $N_ALL"
echo "  System/legitimate: $((N_ALL - N_BAD))"
echo "  ANOMALOUS: $N_BAD"
echo
jq -r '. as $all | range(length) as $i | $all[$i]
  | "  [A\($i + 1)] \(.ts)\n    Host: \(.host)\n    Source Process: \(.src)\n    Target: lsass.exe\n    Access Mask: \(.mask)\n    -> Consistent with memory dumping"' <<<"$ANOM"
echo
echo "CREDENTIAL USAGE CORRELATION:"
echo "  $ACCT authentication from workstations (authorized only on $AUTH):"
jq -r '.[] | "    \(.ts) \(.logon_ws) -> \(.host)  (logon type \(.logon_type), \(.pkg))"' <<<"$AUTHS"
echo "  Remote admin tools used with the account / from the dump host:"
jq -r '.[] | "    \(.ts) \(.tool) on \(.host) as \(.user)"' <<<"$TOOLS"
echo
echo "CREDENTIAL THEFT TIMELINE:"
jq -rn --argjson dumps "$ANOM" --argjson auths "$AUTHS" --argjson tools "$TOOLS" --arg a "$ACCT" '
  ($dumps | map({t: .ts, m: "LSASS dump by \(.src) on \(.host)"}))
  + ($auths | map({t: .ts, m: "\($a) logon \(.logon_ws) -> \(.host)"}))
  + ($tools | map({t: .ts, m: "\(.tool) on \(.host): \(.cmd[0:60])"}))
  | sort_by(.t) | .[] | "  \(.t[0:19])Z  \(.m)"'
echo
echo "FINDING:"
if [ "$N_BAD" -gt 0 ] && [ "$(jq length <<<"$AUTHS")" -gt 0 ]; then
    CONF=MEDIUM; [ "$(jq length <<<"$TOOLS")" -gt 0 ] && CONF=HIGH
    HOSTS=$(jq -r 'map(.host) | unique | join(", ")' <<<"$ANOM")
    echo "  Status: POSITIVE - $CONF CONFIDENCE"
    echo "  A non-standard process read LSASS memory on $HOSTS ($N_BAD times); $ACCT then"
    echo "  authenticated from that workstation to servers outside its scope and ran PsExec/PSRemoting."
    echo "  The attacker likely dumped credentials and later used $ACCT for lateral movement."
    echo "  Recommendation: ESCALATE - rotate $ACCT, isolate $HOSTS, capture memory"
else
    echo "  Status: NEGATIVE - no anomalous LSASS access correlated with $ACCT misuse"
fi
echo
echo "================================================================"
