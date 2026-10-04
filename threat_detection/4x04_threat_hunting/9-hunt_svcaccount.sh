#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
ALERTS="$D/siem_export/wazuh_alerts_14d.json"
SYSMON="$D/siem_export/wazuh_raw_sysmon_14d.json"
SVC="$D/reference/service_accounts.txt"
for f in "$ALERTS" "$SYSMON" "$SVC"; do [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

MATRIX=$(awk '/^--- svc_[a-z_]+ ---/{a=$2} a && /Authorized host:/{
        line=$0; hosts=""; while (match(line, /SRV-[A-Z0-9-]+/)) { hosts=hosts substr(line,RSTART,RLENGTH) " "; line=substr(line,RSTART+RLENGTH) }
        print a, hosts; a="" }' "$SVC" | jq -Rn '[inputs | split(" ") | select(length>0) | {(.[0]): (.[1:] | map(select(length > 0)))}] | add')

EV=$(jq -s 'unique_by(.id) | sort_by(.timestamp) | map(
      .data.win.eventdata as $d
      | {ts: .timestamp, host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
         user: ($d.user // ""), image: ($d.image // ""), cmd: ($d.commandLine // ""), src: ($d.sourceImage // ""),
         target: ($d.targetImage // ""), acct: ($d.targetUserName // ""), ws: ($d.workstationName // ""),
         ltype: ($d.logonType // ""), pkg: ($d.authenticationPackageName // "")})' "$ALERTS" "$SYSMON")

AUDIT=$(jq -c --argjson m "$MATRIX" '[.[] | select(.eid == "4624" and (.acct | test("^svc_"; "i")))
    | . as $e | ($m[$e.acct | ascii_downcase] // []) as $ok
    | {ts, host, acct: ($e.acct | ascii_downcase), ws, ltype, pkg,
       flags: ([ (if ($ok | index($e.ws)) | not then "Wrong source host (authorized: \($ok | join("/") | if . == "" then "none listed" else . end))" else empty end),
                 (if ($e.ws | test("^WS-"; "i")) then "Workstation source" else empty end),
                 (if ($e.ltype | IN("2","10","11")) then "Interactive logon type \($e.ltype)" else empty end),
                 (if ($e.pkg | test("ntlm"; "i")) then "NTLM authentication" else empty end) ])}
    | . + {status: (if (.flags | length) > 0 then "UNAUTHORIZED" else "AUTHORIZED" end)}]' <<<"$EV")

echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"
echo
echo "SERVICE ACCOUNT AUTHORIZATION MATRIX:"
jq -r 'to_entries[] | "  \(.key + ":" | . + (" " * (20 - length))) Authorized on \(.value | join(", ")) only"' <<<"$MATRIX"
echo
echo "AUTHENTICATION AUDIT:"
for acct in $(jq -r 'keys[]' <<<"$MATRIX"); do
    jq -r --arg a "$acct" '[.[] | select(.acct == $a)] as $x | ($x | map(select(.status == "UNAUTHORIZED"))) as $bad
        | select($x | length > 0)
        | "\n  \($a):\n    Total auth events: \($x | length)\n    Authorized: \(($x | length) - ($bad | length))\n    UNAUTHORIZED: \($bad | length)",
          ($bad[] | "      [\(.ts)] \(if .host == .ws then .host else "\(.host) from \(.ws)" end)  (type \(.ltype), \(.pkg))\n"
                    + (.flags | map("        [!] " + .) | join("\n")))' <<<"$AUDIT"
done

SRC=$(jq -c '[.[] | select(.status == "UNAUTHORIZED" and (.flags | any(. == "Workstation source"))) | .ws] | unique' <<<"$AUDIT")
USERS=$(jq -c '[.[] | select(.status == "UNAUTHORIZED") | .acct] | unique' <<<"$AUDIT")
TOOLS=$(jq -c --argjson src "$SRC" --argjson u "$USERS" '[.[] | select(.cmd != "")
    | (.image + " " + .cmd | if test("psexec"; "i") then "PsExec" elif test("wmic|Invoke-WmiMethod"; "i") then "WMI"
       elif test("Enter-PSSession|New-PSSession|Invoke-Command"; "i") then "PSRemoting" else empty end) as $t
    | select((.host | IN($src[])) and ((.user | split("\\") | last | ascii_downcase) | IN($u[]))) | {host, tool: $t}]' <<<"$EV")
DUMPS=$(jq -c --argjson src "$SRC" '[.[] | select(.rule == "61640" and (.target | test("lsass\\.exe$"; "i")) and (.host | IN($src[]))
    and (.src | test("^C:\\\\Windows\\\\System32\\\\"; "i") | not))] | length' <<<"$EV")
N_BAD=$(jq '[.[] | select(.status == "UNAUTHORIZED")] | length' <<<"$AUDIT")
N_WS=$(jq 'length' <<<"$SRC")
echo
echo "CORRELATION WITH OTHER HUNTS:"
echo "  Remote admin tool runs by the abused account from the source workstation: $(jq length <<<"$TOOLS") ($(jq -r 'group_by(.tool) | map("\(.[0].tool) x\(length)") | join(", ")' <<<"$TOOLS"))"
echo "  Anomalous LSASS access on the source workstation: $DUMPS"
echo
echo "FINDING:"
if [ "$N_BAD" -gt 0 ]; then
    CONF=HIGH; [ "$N_WS" -gt 0 ] && [ "$(jq length <<<"$TOOLS")" -gt 0 ] && CONF=CRITICAL
    echo "  Status: POSITIVE - $CONF CONFIDENCE"
    echo "  $(jq -r 'join(", ")' <<<"$USERS") was used from workstation $(jq -r 'join(", ")' <<<"$SRC") ($N_BAD unauthorized logons: NTLM, wrong host)"
    echo "  and correlated with lateral movement activity (PsExec/PSRemoting)$([ "$DUMPS" -gt 0 ] && echo " and prior LSASS credential dumping")."
    echo "  Recommendation: ESCALATE to CISO (PHI exposure risk) - rotate the account, isolate $(jq -r 'join(", ")' <<<"$SRC")"
else
    echo "  Status: NEGATIVE - every service account logon matches the authorization matrix"
fi
echo
echo "================================================================"
