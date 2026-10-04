#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

PIVOT=WS-RECV-03
ACCT=svc_healthsync

CHAIN=$(jq -s -c --arg p "$PIVOT" --arg a "$ACCT" '
  def srv: (.cmd | [scan("SRV-[A-Za-z0-9-]+")] | first) // .host;   # target server named in a command line
  unique_by(.id) | sort_by(.timestamp)
  | map({ts: .timestamp, host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
         user: (.data.win.eventdata.user // ""), cmd: (.data.win.eventdata.commandLine // ""),
         image: (.data.win.eventdata.image // ""), parent: (.data.win.eventdata.parentImage // ""),
         src: (.data.win.eventdata.sourceImage // ""), target: (.data.win.eventdata.targetImage // ""),
         logon: (.data.win.eventdata.targetUserName // ""), ws: (.data.win.eventdata.workstationName // ""),
         pkg: (.data.win.eventdata.authenticationPackageName // "")})
  | map(
      if .host == $p and .rule == "61640" and (.target | test("lsass")) and (.src | test("System32") | not) then
        {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "LSASS memory access by \(.src)"}
      elif .host == $p and (.image | test("\\\\Temp\\\\")) and .cmd != "" then
        {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "credential dump tool run: \(.cmd)"}
      elif .eid == "4624" and .logon == $a and .ws == $p and .pkg == "NTLM" and .host != $p then
        {ph: "LATERAL MOVEMENT", tool: "NTLM", to: .host, what: "\($a) logon \($p) -> \(.host)"}
      elif .host == $p and (.user | test($a)) and (.cmd | test("psexec"; "i")) then
        {ph: "LATERAL MOVEMENT", tool: "PsExec", to: srv, what: "PsExec \($p) -> \(srv)"}
      elif .host == $p and (.user | test($a)) and (.cmd | test("Enter-PSSession")) then
        {ph: "LATERAL MOVEMENT", tool: "PSRemoting", to: srv, what: "PSRemoting \($p) -> \(srv)"}
      elif (.user | test($a)) and (.parent | test("WmiPrvSE")) then
        {ph: "RECONNAISSANCE", tool: "WMI", to: .host, what: "WMI enumeration on \(.host): \(.cmd[0:50])"}
      elif (.user | test($a)) and (.parent | test("wsmprovhost")) and (.cmd | test("Copy-Item")) then
        {ph: "STAGING", tool: "PSRemoting", to: .host, what: "Copy-Item payload \($p) -> \(.host)"}
      else empty end + {ts: .ts})' "$D/siem_export/wazuh_alerts_14d.json" "$D/siem_export/wazuh_raw_sysmon_14d.json")

[ "$(jq length <<<"$CHAIN")" -gt 0 ] || { echo "No anomalous $ACCT / $PIVOT activity found" >&2; exit 0; }

TARGETS=$(jq -c --arg p "$PIVOT" '[.[].to | select(. != $p)] | reduce .[] as $t ([]; if index([$t]) then . else . + [$t] end)' <<<"$CHAIN")
FIRST=$(jq -r '.[0]' <<<"$TARGETS")

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"
echo
echo "ATTACK TIMELINE (UTC):"
jq -r --arg p "$PIVOT" --arg first "$FIRST" '
  map(if .ph != "CREDENTIAL ACCESS" and .to != $first and .to != $p then .ph = "EXPANSION" else . end)
  | group_by(.ph) | sort_by(.[0].ts)[] | "  [\(.[0].ph)]", (.[] | "    \(.ts[0:19])Z  \(.what)")' <<<"$CHAIN"

START=$(jq -r '.[0].ts[0:19] + "Z" | fromdateiso8601' <<<"$CHAIN")
END=$(jq -r '.[-1].ts[0:19] + "Z" | fromdateiso8601' <<<"$CHAIN")
SECS=$((END - START)); PHASES=$(jq '[.[].ph] | unique | length' <<<"$CHAIN")
echo
echo "ATTACK SUMMARY:"
echo "  Pivot host:        $PIVOT"
echo "  Credential used:   $ACCT"
echo "  Targets:           $(jq -r 'join(", ")' <<<"$TARGETS")"
echo "  Tools used:        $(jq -r '[.[] | select(.tool != "LSASS" and .tool != "NTLM") | .tool] | unique | join(", ")' <<<"$CHAIN")"
echo "  Dwell time:        $((SECS / 86400)) days $((SECS % 86400 / 3600)) hours ($(jq -r '.[0].ts[0:16]' <<<"$CHAIN") to $(jq -r '.[-1].ts[0:16]' <<<"$CHAIN") UTC)"
echo
echo "NARRATIVE:"
echo "  $PIVOT was compromised and its LSASS memory dumped, yielding $ACCT credentials."
echo "  The account was used over NTLM from $PIVOT to reach $FIRST (PsExec, WMI recon, PSRemoting staging),"
echo "  then $(jq -r '.[1:] | join(" and ")' <<<"$TARGETS"), ending at the domain controller."
echo
echo "ASSESSMENT:"
if [ "$PHASES" -ge 4 ]; then
    echo "  HEALTHBANE Stage 4 was executed against MedDefense."
    echo "  Confidence: HIGH - $PHASES kill chain phases tie one pivot host to one stolen account."
else
    echo "  Confidence: MEDIUM - only $PHASES kill chain phases linked."
fi
echo
echo "================================================================"
