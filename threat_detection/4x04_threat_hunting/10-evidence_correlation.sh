#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
ALERTS="$D/siem_export/wazuh_alerts_14d.json"
SYSMON="$D/siem_export/wazuh_raw_sysmon_14d.json"
for f in "$ALERTS" "$SYSMON"; do [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

EV=$(jq -s 'unique_by(.id) | sort_by(.timestamp) | map(
      .data.win.eventdata as $d
      | {ts: .timestamp, host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
         user: (($d.user // "") | split("\\") | (last // "") | ascii_downcase),
         image: ($d.image // ""), cmd: ($d.commandLine // ""), parent: ($d.parentImage // ""),
         src: ($d.sourceImage // ""), target: ($d.targetImage // ""),
         acct: (($d.targetUserName // "") | ascii_downcase), ws: ($d.workstationName // ""),
         pkg: ($d.authenticationPackageName // "")})' "$ALERTS" "$SYSMON")

DUMPS=$(jq -c '[.[] | select(.rule == "61640" and (.target | test("lsass\\.exe$"; "i"))
                       and ((.src | test("^C:\\\\Windows\\\\System32\\\\"; "i")) | not))]' <<<"$EV")
PIVOT=$(jq -r '.[0].host // empty' <<<"$DUMPS"); BIN=$(jq -r '.[0].src // empty' <<<"$DUMPS")

ACCT=$(jq -r --arg p "$PIVOT" '[.[] | select(.eid == "4624" and (.acct | test("^svc_")) and .ws == $p and .pkg == "NTLM")]
                               | group_by(.acct) | sort_by(length) | last | (.[0].acct // empty)' <<<"$EV")
[ -n "$PIVOT" ] && [ -n "$ACCT" ] || { echo "No LSASS dump / service-account misuse found - nothing to correlate"; exit 0; }

CHAIN=$(jq -c --arg p "$PIVOT" --arg a "$ACCT" --arg bin "$BIN" '
  def target: ([.cmd | scan("\\\\\\\\(SRV-[A-Za-z0-9-]+)|-ComputerName ([A-Za-z0-9-]+)")] | (.[0] // []) | map(select(. != null)) | (.[0] // null)) // .host;
  [.[] | . as $x
   | (if   $x.src == $bin and $x.host == $p then {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "LSASS memory read by \($bin)"}
      elif $x.image == $bin and $x.host == $p and $x.cmd != "" then {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "dump tool run: \($x.cmd)"}
      elif $x.eid == "4624" and $x.acct == $a and $x.ws == $p and $x.host != $p then {ph: "LATERAL MOVEMENT", tool: "NTLM", to: $x.host, what: "\($a) logon \($p) -> \($x.host)"}
      elif $x.user == $a and ($x.image + $x.cmd | test("psexec"; "i")) and $x.cmd != "" then ($x | target) as $t | {ph: "LATERAL MOVEMENT", tool: "PsExec", to: $t, what: "PsExec \($p) -> \($t)"}
      elif $x.user == $a and ($x.cmd | test("Enter-PSSession|New-PSSession")) then ($x | target) as $t | {ph: "LATERAL MOVEMENT", tool: "PSRemoting", to: $t, what: "PSRemoting \($p) -> \($t)"}
      elif $x.user == $a and ($x.parent | test("WmiPrvSE"; "i")) then {ph: "RECONNAISSANCE", tool: "WMI", to: $x.host, what: "WMI on \($x.host): \($x.cmd[0:50])"}
      elif $x.user == $a and ($x.parent | test("wsmprovhost"; "i")) and ($x.cmd | test("Copy-Item")) then {ph: "STAGING", tool: "PSRemoting", to: $x.host, what: "Copy-Item payload \($p) -> \($x.host)"}
      else null end) as $m
   | select($m != null) | {ts: $x.ts} + $m]' <<<"$EV")

TARGETS=$(jq -c --arg p "$PIVOT" '[.[] | select(.to != $p) | .to] | reduce .[] as $t ([]; if index([$t]) then . else . + [$t] end)' <<<"$CHAIN")
FIRST=$(jq -r '.[0]' <<<"$TARGETS")

echo "================================================================"
echo "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction"
echo "================================================================"
echo
echo "ATTACK TIMELINE (UTC):"
jq -r --arg p "$PIVOT" --arg first "$FIRST" '
  map(if .ph != "CREDENTIAL ACCESS" and .to != $first and .to != $p then .ph = "EXPANSION" else . end)
  | group_by(.ph) | sort_by(.[0].ts)[] | "  [\(.[0].ph)]", (.[] | "    \(.ts[0:19])Z  \(.what)")' <<<"$CHAIN"

START=$(jq -r '.[0].ts[0:19] + "Z" | fromdateiso8601' <<<"$CHAIN"); END=$(jq -r '.[-1].ts[0:19] + "Z" | fromdateiso8601' <<<"$CHAIN")
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
echo "  $PIVOT was compromised and LSASS memory dumped by ${BIN##*\\}, yielding $ACCT credentials."
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
