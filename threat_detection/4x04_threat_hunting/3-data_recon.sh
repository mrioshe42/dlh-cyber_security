#!/bin/bash

D=$(dirname "$(readlink -f "$0")"); [ -d "$D/siem_export" ] || D="$D/4x04"
A="$D/siem_export/wazuh_alerts_14d.json"; S="$D/siem_export/wazuh_raw_sysmon_14d.json"
command -v jq >/dev/null && [ -r "$A" ] && [ -r "$S" ] || { echo "missing jq or siem_export files" >&2; exit 1; }

jq -rs --arg a "$(wc -l <"$A")" --arg s "$(wc -l <"$S")" '
  def pad($n): tostring | . + (" " * ($n - length));
  def rpad($n): tostring | (" " * ($n - length)) + .;
  def dist(f): group_by(f) | map({k:(.[0]|f), n:length}) | sort_by(-.n);
  def ed: .data.win.eventdata // {};
  def txt: [(ed|.image,.commandLine,.parentImage,.targetImage)] | map(. // "") | join(" ");
  unique_by(.id) | sort_by(.timestamp) as $e
  | ($e|length) as $T
  | ($e|map(.timestamp[0:19]+"Z"|fromdateiso8601)) as $ts
  | def cov($name; f): ($e|map(select(f))|length) as $n
      | "  \($name|pad(19)) \(if $n>0 then "[OK]  " else "[GAP] " end) \($n) matching events";
  "================================================================",
  "   DATA RECONNAISSANCE - MedDefense SIEM Export",
  "================================================================\n",
  "DATASET METADATA:",
  "  Total events:   \($T) (\($a) alerts + \($s) raw sysmon lines, de-duplicated by id)",
  "  First event:    \($e[0].timestamp)",
  "  Last event:     \($e[-1].timestamp)",
  "  Duration:       \((($ts[-1]-$ts[0])/86400)|floor) days",
  "  Format:         JSON Lines (one Wazuh event per line)\n",
  "TOP 10 EVENT TYPES:",
  (($e|dist(.rule.id + "  " + (.rule.description|sub("^Sysmon - Event: [0-9]+ - ";"Sysmon: ")|sub("\\.$";""))))[:10][] | "  \(.k)  (\(.n))"),
  "\nSOURCE HOST DISTRIBUTION (events per agent):",
  (($e|dist(.agent.name))[] | "  \((.k+":")|pad(16)) \(.n)"),
  "\nSEVERITY DISTRIBUTION (rule.level):",
  (($e|dist(.rule.level)|sort_by(.k))[] | "  level \(.k): \(.n)"),
  "\nHOURLY DISTRIBUTION (UTC):",
  ($e|group_by(.timestamp[11:13])|map({h:.[0].timestamp[11:13], n:length}) as $h
    | ($h|map(.n)|max) as $m | ($h[] | "  \(.h):00 \(.n|rpad(5)) \("#" * (.n*40/$m|ceil))")),
  "\nHYPOTHESIS COVERAGE MATRIX (required evidence present in data):",
  cov("H1 (PsExec):";       (txt|test("psexec";"i"))),
  cov("H2 (LSASS):";        (.rule.id=="61640" and (ed.targetImage//""|test("lsass";"i")))),
  cov("H3 (WMI):";          (txt|test("wmic|wmiprvse";"i"))),
  cov("H4 (PSRemoting):";   (txt|test("wsmprovhost|PSSession|Invoke-Command";"i"))),
  cov("H5 (Svc Accounts):"; (ed.targetUserName//""|test("^svc_";"i")) and .data.win.system.eventID=="4624"),
  "\n================================================================"' "$A" "$S"
