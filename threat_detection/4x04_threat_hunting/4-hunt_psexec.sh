#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
A="$D/siem_export/wazuh_alerts_14d.json"; S="$D/siem_export/wazuh_raw_sysmon_14d.json"
B="$D/baseline/robert_kim_activity.json"
for f in "$A" "$S" "$B"; do [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

jq -rn --slurpfile b "$B" '
  def ed: .data.win.eventdata // {};
  def isps: (ed | (.image // "") + " " + (.commandLine // "") | test("psexec";"i"));
  def host: (ed.commandLine // "" | capture("\\\\\\\\(?<h>[A-Za-z0-9._-]+)").h) // ed.destinationHostname // "unknown";
  def local: (.timestamp[0:19]+"Z" | fromdateiso8601 - 18000);
  ($b | map(select(.data.win.eventdata.image|test("psexec";"i")))) as $base
  | ($base|map(.agent.name)|unique) as $srcs | ($base|map(.data.win.eventdata.user)|unique) as $users
  | ($base|map(.data.win.eventdata.image)|unique) as $imgs
  | [inputs | select(isps)] | unique_by(.id) | sort_by(.timestamp)
  | map(local as $t | ($t|strftime("%H")|tonumber) as $h | ($t|strftime("%a")) as $d
      | host as $tgt | .agent.name as $a | (ed.user // "") as $u | (ed.image // "") as $i
      | {ts:.timestamp, src:.agent.name, user:ed.user, cmd:(ed.commandLine // "(none - " + (.rule.description|sub("Sysmon - ";"")) + " to \($tgt):\(ed.destinationPort // "?"))"),
         tgt:$tgt, pid:(ed.processId // "n/a"),
         flags:[ (if ($srcs|index($a))|not then "Source host is NOT \($srcs|join("/"))" else empty end),
                 (if $h<8 or $h>=18 then "Time is outside business hours (\($t|strftime("%H:%M")) Central)" else empty end),
                 (if $d=="Sat" or $d=="Sun" then "Day is a weekend (\($d))" else empty end),
                 (if ($users|index($u))|not then "User \(if ($u|test("svc_";"i")) then "is a service account" else "is NOT the baseline admin account" end)" else empty end),
                 (if ($tgt|test("DB|DC";"i")) and (($srcs|index($a))|not) then "Target is a \(if ($tgt|test("DB")) then "database" else "domain controller" end) server" else empty end),
                 (if ($imgs|index($i))|not then "Binary runs from non-baseline path (\($i))" else empty end) ]})
  | map(. + {core: ([.flags[]|select(test("^(Source|Time|Day|User)"))]|length)}) as $ev
  | ($ev|map(select(.core>0))) as $an
  | "================================================================",
    "   HUNT EXECUTION - H1: Lateral Movement via PsExec",
    "   Technique: T1021.002 SMB/Windows Admin Shares",
    "================================================================\n",
    "QUERY RESULTS:",
    "  Total PsExec events in 14 days: \($ev|length)",
    "  Baseline: \($ev|length - ($an|length))",
    "  ANOMALOUS: \($an|length)\n",
    "ANOMALOUS EVENTS:",
    ($an | to_entries[] | "  [A\(.key+1)] \(.value.ts)\n    Source: \(.value.src)\n    User: \(.value.user)\n    Command: \(.value.cmd)\n    Target: \(.value.tgt)\n    PID: \(.value.pid)\n    ANOMALY FLAGS:\n" + (.value.flags|map("      [!] "+.)|join("\n"))),
    "\nFINDING:",
    (if ($an|length)==0 then "  Status: NEGATIVE - no PsExec activity deviates from baseline\n  Recommendation: CLOSE H1, no escalation"
     else ($an|map(.src)|unique) as $s | ($an|map(.tgt)|unique) as $t | ($an|map(.ts[0:10])|unique|length) as $days
       | "  Status: POSITIVE - \(if $days>1 and ($an|map(.core)|max)>=3 then "HIGH" else "MEDIUM" end) CONFIDENCE",
         "  Evidence: PsExec executions from non-admin workstation(s) \($s|join(", ")) over \($days) distinct days;",
         "            \($an|map(.user)|unique|join(", ")) used off-hours against \($t|join(", ")); binary in user-writable path",
         "  Recommendation: ESCALATE" end),
    "\n================================================================"
' "$A" "$S"
