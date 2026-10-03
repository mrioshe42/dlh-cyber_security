#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/baseline" ] || D="$D/4x04"
F="$D/baseline/robert_kim_activity.json"
command -v jq >/dev/null && [ -r "$F" ] || { echo "missing jq or $F" >&2; exit 1; }

jq -rs '
  def n: length;
  def tbl(f): group_by(f)|map("  \(.[0]|f): \(n)")|sort_by(-(split(": ")[1]|tonumber))[];
  def cnt(f): map(select(f))|n;
  map({tool:.hunt_meta.tool, src:.hunt_meta.source_host, dst:.hunt_meta.target_host,
       user:.data.win.eventdata.user,
       t:((.timestamp[0:19]+"Z")|fromdateiso8601-18000)}
      | .hour=(.t|strftime("%H")|tonumber) | .day=(.t|strftime("%a"))) as $e
  | ($e|n) as $T | ($e|cnt(.hour>=8 and .hour<18)) as $in | ($e|cnt(.src!="WS-ADMIN-01")) as $oth
  | ($e|cnt(.user|test("svc_";"i"))) as $svc
  | "================================================================",
    "   BASELINE PROFILE - Robert Kim (IT Administrator)",
    "   Source: baseline/robert_kim_activity.json",
    "================================================================\n",
    "TOOL USAGE SUMMARY:",
    (("PsExec","WMI","PSRemoting") as $t | "  \($t) events:\(" "*(14-($t|length))) \($e|cnt(.tool==$t))"),
    "  Total admin events:    \($T)\n",
    "SOURCE HOST:", ($e|tbl(.src)), "  Other hosts: \($oth)",
    (if $oth==0 then "  -> BASELINE: All admin activity originates from WS-ADMIN-01" else empty end),
    "\nTIME DISTRIBUTION (Central):",
    "  08:00-18:00: \($in)", "  18:00-08:00: \($T-$in)",
    ($e|group_by(.hour)[]|"    \(.[0].hour|tostring|("0"+.)[-2:]):00  \(n)"),
    (if $in==$T then "  -> BASELINE: Zero admin activity outside business hours" else empty end),
    "\nDAY-OF-WEEK DISTRIBUTION:",
    (("Mon","Tue","Wed","Thu","Fri","Sat","Sun") as $d
      | ($e|map(select(.day==$d))) as $x
      | "  \($d): \($x|n)  (PsExec \($x|cnt(.tool=="PsExec")), WMI \($x|cnt(.tool=="WMI")), PSRemoting \($x|cnt(.tool=="PSRemoting")))"),
    "  -> Tue = software deployment, Thu = patching; WMI inventory daily; no weekend activity\n",
    "TARGET HOSTS:", ($e|tbl(.dst)),
    "\nUSER ACCOUNTS:", ($e|tbl(.user)), "  Service accounts: \($svc)",
    (if $svc==0 then "  -> BASELINE: Never uses service accounts interactively" else empty end),
    "\nBASELINE SUMMARY:",
    "  Normal source host:  WS-ADMIN-01 (WS-ADMIN-02 only on written failover)",
    "  Normal time window:  Mon-Fri 08:00-18:00 Central",
    "  Normal account:      \($e|map(.user)|unique|join(", "))",
    "  Normal tools:        \($e|map(.tool)|unique|join(", "))",
    "  Normal targets:      \($e|map(.dst)|unique|join(", "))",
    "\nANOMALY DETECTION CRITERIA:",
    "  [!] Admin tool from any host other than WS-ADMIN-01",
    "  [!] Admin tool usage outside business hours or on weekends",
    "  [!] Service account used interactively from workstation",
    "  [!] WMI targeting unusual hosts (not in baseline target list)",
    "  [!] Admin tool run under an account other than the named admin account",
    "\n================================================================"' "$F"
