#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
SA="$D/reference/service_accounts.txt"
command -v jq >/dev/null && [ -r "$SA" ] || { echo "missing jq or $SA" >&2; exit 1; }
ACCT=svc_healthsync
AUTH=$(awk -v a="--- $ACCT ---" '$0==a{f=1} f&&/Authorized host:/{print $3; exit}' "$SA")  # from account matrix

jq -rn --arg acct "$ACCT" --arg auth "$AUTH" '
  def ed: .data.win.eventdata // {};
  def sys: ["csrss.exe","services.exe","svchost.exe","msmpeng.exe","wmiprvse.exe","wininit.exe"];  # HC3 standard set
  def tool: (ed|(.image//"")+" "+(.commandLine//"")) | if test("psexec";"i") then "PsExec"
      elif test("wmic|Invoke-WmiMethod|wmiprvse";"i") then "WMI"
      elif test("Enter-PSSession|New-PSSession|Invoke-Command|wsmprovhost";"i") then "PSRemoting" else null end;
  [inputs] | unique_by(.id) | sort_by(.timestamp) as $e
  | ($e|map(select(.rule.id=="61640" and (ed.targetImage//""|test("lsass\\.exe$";"i"))))) as $ls
  | ($ls|map(select((ed.sourceImage|test("^C:\\\\Windows\\\\System32\\\\";"i")) and (ed.sourceImage|split("\\")|last|ascii_downcase|IN(sys[]))))) as $ok
  | ($ls - $ok) as $an
  | ($an|map(.agent.name)|unique) as $dh
  | ($e|map(select(.data.win.system.eventID=="4624" and (ed.targetUserName//""|ascii_downcase)==$acct and (ed.workstationName//"")!=$auth))) as $auths
  | ($e|map(select(tool!=null and .agent.name!="WS-ADMIN-01" and (((ed.user//"")|test($acct;"i")) or (.agent.name|IN($dh[])))))) as $tools
  | "================================================================",
    "   HUNT EXECUTION - H2: Credential Access (LSASS)",
    "   Technique: T1003.001 LSASS Memory",
    "================================================================\n",
    "LSASS ACCESS EVENTS:",
    "  Total LSASS access events: \($ls|length)\n  System/legitimate: \($ok|length)\n  ANOMALOUS: \($an|length)\n",
    ($an|to_entries[] | .key as $i | .value as $v | ($v|ed) as $d
      | "  [A\($i+1)] \($v.timestamp)\n    Host: \($v.agent.name)\n    Source Process: \($d.sourceImage)\n    Target: lsass.exe\n    Access Mask: \($d.grantedAccess)\n    -> \(if ($d.grantedAccess|ltrimstr("0x")|test("[13579bdf]0$")) then "VM_READ (0x10) by non-standard binary - consistent with memory dumping" else "Unusual source process" end)"),
    "\nCREDENTIAL USAGE CORRELATION:",
    "  \($acct) (authorized only on \($auth)) authentication from workstations:",
    ($auths|map(select(.agent.name!=ed.workstationName))[] | "    \(.timestamp) \(ed.workstationName) -> \(.agent.name)  (type \(ed.logonType), \(ed.authenticationPackageName))"),
    "  Remote admin tools from the dump host / using the account:",
    ($tools[] | select(ed.user|test("system$";"i")|not) | "    \(.timestamp) \(tool) on \(.agent.name) as \(ed.user)"),
    "\nCREDENTIAL THEFT TIMELINE:",
    (($an|map({t:.timestamp, m:"LSASS dump by \(ed.sourceImage) on \(.agent.name)"}))
     + ($auths|map(select(.agent.name!=ed.workstationName))|map({t:.timestamp, m:"\($acct) NTLM logon \(ed.workstationName) -> \(.agent.name)"}))
     + ($tools|map(select(ed.commandLine)|{t:.timestamp, m:"\(tool) on \(.agent.name): \(ed.commandLine|.[0:60])"}))
     | sort_by(.t)[] | "  \(.t[0:19])Z  \(.m)"),
    "\nFINDING:",
    (if ($an|length)>0 and ($auths|length)>0
     then "  Status: POSITIVE - \(if ($tools|length)>0 then "HIGH" else "MEDIUM" end) CONFIDENCE\n  \($an[0]|ed.sourceImage) read LSASS on \($dh|join(", ")) (\($an|length)x); \($acct) then authenticated over NTLM\n  from that workstation to servers outside its scope and ran PsExec/PSRemoting. The attacker likely\n  dumped credentials and later used \($acct) for lateral movement.\n  Recommendation: ESCALATE - rotate \($acct), isolate \($dh|join(", ")), capture memory"
     else "  Status: NEGATIVE - no anomalous LSASS access correlated with \($acct) misuse" end),
    "\n================================================================"
' "$D/siem_export/wazuh_alerts_14d.json" "$D/siem_export/wazuh_raw_sysmon_14d.json"
