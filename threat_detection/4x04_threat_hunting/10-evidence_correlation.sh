#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

jq -rs '
  def tgt: (.cmd | capture("\\\\\\\\(?<h>SRV-[A-Za-z0-9-]+)").h) // (.cmd | capture("-ComputerName (?<h>[A-Za-z0-9-]+)").h) // .host;
  def secs: .[0:19] + "Z" | fromdateiso8601;
  unique_by(.id) | sort_by(.timestamp) | map(.data.win.eventdata as $d | {
      ts: .timestamp, host: .agent.name, rule: .rule.id, eid: .data.win.system.eventID,
      user: (($d.user // "") | split("\\") | last // "" | ascii_downcase), image: ($d.image // ""), cmd: ($d.commandLine // ""),
      parent: ($d.parentImage // ""), src: ($d.sourceImage // ""), target: ($d.targetImage // ""),
      acct: (($d.targetUserName // "") | ascii_downcase), ws: ($d.workstationName // ""), pkg: ($d.authenticationPackageName // "")}) as $e
  | ($e | map(select(.rule == "61640" and (.target | test("lsass\\.exe$"; "i")) and (.src | test("^C:\\\\Windows\\\\System32\\\\"; "i") | not)))) as $dumps
  | ($dumps[0].host) as $p | ($dumps[0].src) as $bin
  | ($e | map(select(.eid == "4624" and (.acct | test("^svc_")) and .ws == $p and .pkg == "NTLM")) | group_by(.acct) | max_by(length)[0].acct) as $a
  | if $p == null or $a == null then "No LSASS dump / service-account misuse found - nothing to correlate" else
    # Tag each anomalous event (H1 PsExec, H2 LSASS, H3 WMI, H4 PSRemoting, H5 account use) with a kill chain phase
    ($e | map(. as $x | (
        if   $x.src == $bin and $x.host == $p then {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "LSASS memory read by \($bin)"}
        elif $x.image == $bin and $x.host == $p and $x.cmd != "" then {ph: "CREDENTIAL ACCESS", tool: "LSASS", to: $p, what: "dump tool run: \($x.cmd)"}
        elif $x.eid == "4624" and $x.acct == $a and $x.ws == $p and $x.host != $p then {ph: "LATERAL MOVEMENT", tool: "NTLM", to: $x.host, what: "\($a) logon \($p) -> \($x.host)"}
        elif $x.user == $a and ($x.image + $x.cmd | test("psexec"; "i")) and $x.cmd != "" then {ph: "LATERAL MOVEMENT", tool: "PsExec", to: ($x | tgt), what: "PsExec \($p) -> \($x | tgt)"}
        elif $x.user == $a and ($x.cmd | test("Enter-PSSession|New-PSSession")) then {ph: "LATERAL MOVEMENT", tool: "PSRemoting", to: ($x | tgt), what: "PSRemoting \($p) -> \($x | tgt)"}
        elif $x.user == $a and ($x.parent | test("WmiPrvSE"; "i")) then {ph: "RECONNAISSANCE", tool: "WMI", to: $x.host, what: "WMI on \($x.host): \($x.cmd[0:50])"}
        elif $x.user == $a and ($x.parent | test("wsmprovhost"; "i")) and ($x.cmd | test("Copy-Item")) then {ph: "STAGING", tool: "PSRemoting", to: $x.host, what: "Copy-Item payload \($p) -> \($x.host)"}
        else empty end) as $m | {ts: $x.ts} + $m)) as $c
    | ($c | map(select(.to != $p) | .to) | reduce .[] as $t ([]; if index($t) then . else . + [$t] end)) as $targets
    | ($c | map(if .ph != "CREDENTIAL ACCESS" and .to != $targets[0] and .to != $p then .ph = "EXPANSION" else . end)) as $tl
    | ($c | map(.ph) | unique | length) as $phases
    | (($c[-1].ts | secs) - ($c[0].ts | secs)) as $dwell
    | "================================================================",
      "   EVIDENCE CORRELATION - HEALTHBANE Stage 4 Reconstruction",
      "================================================================\n",
      "ATTACK TIMELINE (UTC):",
      ($tl | group_by(.ph) | sort_by(.[0].ts)[] | "  [\(.[0].ph)]", (.[] | "    \(.ts[0:19])Z  \(.what)")),
      "\nATTACK SUMMARY:",
      "  Pivot host:        \($p)",
      "  Credential used:   \($a)",
      "  Targets:           \($targets | join(", "))",
      "  Tools used:        \($c | map(select(.tool != "LSASS" and .tool != "NTLM") | .tool) | unique | join(", "))",
      "  Dwell time:        \($dwell / 86400 | floor) days \($dwell % 86400 / 3600 | floor) hours (\($c[0].ts[0:16]) to \($c[-1].ts[0:16]) UTC)",
      "\nNARRATIVE:",
      "  \($p) was compromised and LSASS memory dumped by \($bin | split("\\") | last), yielding \($a) credentials.",
      "  The account was used over NTLM from \($p) to reach \($targets[0]) (PsExec, WMI recon, PSRemoting staging),",
      "  then \($targets[1:] | join(" and ")), ending at the domain controller.",
      "\nASSESSMENT:",
      (if $phases >= 4 then "  HEALTHBANE Stage 4 was executed against MedDefense.\n  Confidence: HIGH - \($phases) kill chain phases tie one pivot host to one stolen account."
       else "  Confidence: MEDIUM - only \($phases) kill chain phases linked." end),
      "\n================================================================" end
' "$D/siem_export/wazuh_alerts_14d.json" "$D/siem_export/wazuh_raw_sysmon_14d.json"
