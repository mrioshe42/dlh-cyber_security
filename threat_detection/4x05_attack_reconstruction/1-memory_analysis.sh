#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
MEM="$BASE/ir_evidence/memory_artifacts.txt"
DISK="$BASE/ir_evidence/disk_forensics_report.txt"
IOC="$BASE/reference/healthbane_ioc_master.json"
PREV="$BASE/previous_findings"
for f in "$MEM" "$IOC"; do [ -f "$f" ] || { echo "Missing: $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
sec() { grep -m1 -E "^SECTION $1 " "$MEM" | sed -E 's/^SECTION ([0-9]+) -- [A-Z ]+ *\(([a-z+ .]*).*/\2 (S\1)/; s/ +\)/)/'; }   # "netscan (S3)"
ioc_ids()  { jq -r --arg t "$1" '.iocs[] | select(.value | ascii_downcase | contains($t | ascii_downcase)) | .id' "$IOC" | head -1; }
prev_hit() { grep -rilF -- "$1" "$PREV" 2>/dev/null | head -1 | xargs -r basename | grep -oE '^4x0[0-9]'; }

declare -A TECH; KNOWN=0; NEW=0; MOD=0
status() {
    local id ph; id=$(ioc_ids "$1"); ph=$(prev_hit "$1")
    if   [ "$2" = MOD ]; then ST="MODIFIED (variant of ${id:-$ph})"; MOD=$((MOD + 1))
    elif [ -n "$id" ];   then ST="KNOWN (${id})"; KNOWN=$((KNOWN + 1))
    elif [ -n "$ph" ];   then ST="KNOWN (${ph}, not in IOC master)"; KNOWN=$((KNOWN + 1))
    else ST="NEW"; NEW=$((NEW + 1)); fi
}
tech() { for t in $1; do TECH[$t]=1; done; }

pid_block() { awk -v p="$1" '$1==p && $2 ~ /^[0-9]+$/ {f=1; print; next}
    f && (/^[0-9]+ +[0-9]+ +[A-Za-z]/ || /^\(exited\)/ || /^# ---/) {exit} f {print}' <(sed -n '/^SECTION 2 /,/^SECTION 3 /p' "$MEM"); }
cmdline_of() { awk -v p="$1" '$1=="PID" && $2==p {f=1; next} f && /^PID |^SECTION|^$/ {if (n) exit; next} f {n=1; print}' <(sed -n '/^SECTION 4 /,/^SECTION 5 /p' "$MEM"); }
decode_b64() { base64 -d 2>/dev/null <<< "$1" | iconv -f UTF-16LE -t UTF-8 2>/dev/null | tr '\r\n' '  ' | sed 's/  */ /g'; }
ioc_sha() { jq -r '.iocs[] | select(.type=="sha256") | .value' "$IOC"; }

bar
echo "   MEMORY ARTIFACT ANALYSIS - $(grep -m1 -oE 'Hostname: +[A-Z0-9-]+' "$MEM" | awk '{print $2}')"
echo "   Source: ir_evidence/memory_artifacts.txt   Capture: $(grep -m1 'Capture date' "$MEM" | sed -E 's/^[^:]*: *//')"
bar
echo

echo "PROCESS ANALYSIS: ($(sec 2))"
printf '  %-6s %-20s %-11s %-12s %s\n' PID Process Status ATT\&CK IOC
mode=std; legit=0
while IFS= read -r line; do
    case "$line" in
        "# --- SUSPICIOUS"*) mode=susp; continue ;;
        "# --- PROCESSES THAT EXITED"*) mode=exited; continue ;;
    esac
    if [[ "$line" =~ ^\(exited\)[[:space:]]+-[[:space:]]+([A-Za-z0-9_.]+) ]]; then pid="-"; name="${BASH_REMATCH[1]}"; mode=exited
    elif [[ "$line" =~ ^([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([A-Za-z0-9_.]+) ]]; then pid="${BASH_REMATCH[1]}"; name="${BASH_REMATCH[3]}"
    else continue; fi
    if [ "$mode" = std ] || [ "$name" = conhost.exe ]; then legit=$((legit + 1)); continue; fi
    blk=$( [ "$pid" = - ] && awk -v n="$name" '$0 ~ "^\\(exited\\) +- +"n {f=1; print; next} f && (/^\(exited\)/ || /^SECTION/) {exit} f {print}' "$MEM" || pid_block "$pid")
    notes=()
    case "$name" in
        svchost_update.exe) at="T1036.005 T1055.012"; term="$name"
            h=$(grep -oE '[0-9a-f]{32}' <<< "$blk" | head -2 | tr -d '\n')
            if [ -n "$h" ] && ioc_sha | grep -qi "$h"; then status "$name"; st=$ST; notes+=("hash = $(jq -r --arg h "$h" '.iocs[] | select(.value | contains($h)) | .id' "$IOC")")
            elif [ -n "$h" ]; then status "$name" MOD; st=$ST; notes+=("hash $h not in IOC master")
            else status "$name"; st=$ST; fi
            grep -q forged <<< "$blk" && notes+=("PPID forged")
            grep -q "PID $pid" <(sed -n '/^SECTION 5 /,/^SECTION 6 /p' "$MEM") && notes+=("malfind RWX/MZ") ;;
        powershell.exe) at="T1059.001 T1027"
            b64=$(cmdline_of "$pid" | grep -oE '[A-Za-z0-9+/=]{60,}' | tr -d '\n')
            dec=$(decode_b64 "$b64"); term=$(grep -oE '[A-Za-z_]+\.ps1' <<< "$dec" | head -1)
            status "${term:-powershell -encodedcommand}"; st=$ST; notes+=("child of RAT; decodes to ${dec:0:60}...") ;;
        debug_tool.exe) at="T1003.001"; status "$name"; st=$ST; notes+=("exited; LSASS handle 0x1010") ;;
        PsExec64.exe)   at="T1021.002"; status "$name"; st=$ST; notes+=("exited; run from Public\\Tmp") ;;
        cmd.exe)        at="T1059.003"; st="-"; notes+=("parent of PsExec64/wmic across lateral-movement events") ;;
        *)              at="-"; status "$name"; st=$ST; notes+=("unclassified non-standard process") ;;
    esac
    tech "$at"
    printf '  %-6s %-20s %-11s %-12s %s\n' "$pid" "$name" "$([ "$name" = cmd.exe ] && echo LEGITIMATE || echo SUSPICIOUS)" "${at// /,}" "$st"
    [ "$name" != cmd.exe ] && echo "         -> $(printf '%s; ' "${notes[@]}" | sed 's/; $//' | cut -c1-110)"
done < <(sed -n '/^SECTION 2 /,/^SECTION 3 /p' "$MEM")
echo "  + $legit standard/user processes LEGITIMATE"
echo

echo "NETWORK CONNECTIONS (at capture): ($(sec 3))"
printf '  %-14s %-18s %-6s %-12s %-18s %s\n' Source Dest Port State Process "IOC match"
benign=0
while read -r proto local remote state pid proc flag _; do
    [[ "$proto" =~ ^TCP$ ]] || continue
    [ "$state" = LISTEN ] && continue
    ip="${remote%:*}"; port="${remote##*:}"
    id=$(jq -r --arg ip "$ip" '.iocs[] | select(.type=="ipv4" and .value==$ip) | "\(.id) \(.sources | join(","))"' "$IOC" | head -1)
    if [ -n "$id" ]; then m="KNOWN (${id% *}, ${id#* })"; KNOWN=$((KNOWN + 1)); tech T1071.001
    elif [ "$flag" = "[B]" ] || [[ "$ip" =~ ^10\. ]]; then benign=$((benign + 1)); continue
    else m="NEW"; NEW=$((NEW + 1)); [[ "$port" =~ ^(80|443|53)$ ]] && tech T1071.001 || tech T1571; fi
    printf '  %-14s %-18s %-6s %-12s %-18s %s\n' "${local%:*}" "$ip" "$port" "$state" "$proc" "$m"
    [ "$m" = NEW ] && newip="$ip:$port ($proc, PID $pid)" && newport=$port
done < <(sed -n '/^SECTION 3 /,/^SECTION 4 /p' "$MEM" | grep -E '^(TCP|UDP) ')
echo "  + $benign benign connections omitted"
[ -n "$newip" ] && echo "  NEW: $newip, non-standard port = secondary C2 (T1571, PROBABLE; flagged in IR notes: $(grep -c "${newip%%:*}" "$BASE"/ir_evidence/ir_team_notes.txt) mentions)"
echo

echo "CREDENTIAL ACCESS INDICATORS: ($(sec 7), $(sec 8))"
mods=$(sed -n '/^SECTION 8 /,/^SECTION 9 /p' "$MEM" | grep -ciE '(mimikatz|sekurlsa|wce|comsvcs|procdump)[a-z0-9_]*\.dll')
echo "  [*] Credential-tool DLLs loaded: $mods"
while IFS= read -r l; do
    acc=$(grep -oE '0x[0-9A-Fa-f]{4}' <<< "$l" | head -1); who=$(awk '{print $1}' <<< "$l")
    status "$who"; st=$ST; tech T1003.001
    echo "  [*] $who -> lsass.exe handle $acc | T1003.001 | $st (confirms 4x04 H4)"
done < <(sed -n '/^SECTION 7 /,/^SECTION 8 /p' "$MEM" | grep -E '^ *[a-z_]+\.exe -> Process +<0x1010>')
echo

echo "PERSISTENCE MECHANISMS: ($(sec 9))"
k2=$(sed -n '/^\[K2\]/,/^\[K3\]/p' "$MEM")
tname=$(grep -oE 'Data: +\\[A-Za-z ]+' <<< "$k2" | sed 's/Data: *\\//')
guid=$(grep -oE '\{[0-9A-F-]{36}\}' <<< "$k2" | head -1)
lw=$(grep -m1 'Last Write Time' <<< "$k2" | sed -E 's/^ *Last Write Time: *//; s/ *\(.*//')
xml=$(sed -n '/SCHEDULED TASK XML/,/^SECTION 5/p' "$DISK" 2>/dev/null)
xv() { grep -oE "<$1>[^<]*" <<< "$xml" | head -1 | sed "s/<$1>//"; }
reg=$(xv Date); trig=$(xv StartBoundary); every=$(xv DaysInterval)
cmd=$(xv Command | sed 's/.*\\//'); args=$(xv Arguments)
dec=$(decode_b64 "$(grep -oE '[A-Za-z0-9+/=]{60,}' <<< "$args" | head -1)")
status "$tname"; st=$ST; tech T1053.005
echo "  Scheduled Task: \"$tname\"  [$guid]"
echo "    Trigger: $([ -n "$trig" ] && echo "daily (every ${every:-?} day) at ${trig#*T}" || echo "not in memory file (task XML is on disk)")"
echo "    Action: ${cmd:-?} -enc ... = ${dec:0:90}"
echo "    Created: ${reg%.*} CDT (registry $lw)   Hidden: $(xv Hidden)"
echo "    ATT&CK: T1053.005 Scheduled Task/Job   Status: $st"
hunt_ts() { grep -m1 "$1" "$PREV"/*hunt* | sed -E 's/^ *([0-9-]+) +([0-9:]+) CDT.*/\1 \2/'; }
hrs() { echo $(( ($(date -u -d "${reg%.*} -0500" +%s) - $(date -u -d "$1 -0500" +%s)) / 3600 )); }
d1=$(hunt_ts 'Credential dump #1'); p1=$(hunt_ts 'PsExec session #1')
[ -n "$d1" ] && [ -n "$reg" ] && echo "  TIMING: $(hrs "$d1") h after credential dump #1; $(hrs "$p1") h after PsExec #1."
k1=$(sed -n '/^\[K1\]/,/^\[K2\]/p' "$MEM")
status 'Run\HealthSync'; tech T1547.001
echo "  Run-key HKCU\\...\\Run\\HealthSync | T1547.001 | $ST"
echo

echo "OTHER MEMORY FINDINGS:"
k5=$(sed -n '/^\[K5\]/,/^SECTION 10/p' "$MEM")
status 'Defender exclusion'; tech T1562.001
echo "  Defender exclusion C:\\Windows\\Temp | T1562.001 | $ST"
frag=$(grep -oE '"clear_logs":[a-z]+' "$MEM" | head -1)
if [ -n "$frag" ]; then status 'wevtutil'; tech T1070.001; echo "  Exfiltrator config residue ($frag) | T1070.001 | $ST"; fi
status 'sync_healthdata.ps1'; tech "T1005 T1074.001 T1560.001"
echo "  Exfiltrator script (SQL, Compress-Archive, staging) | T1005,T1074.001,T1560.001 | $ST"
if grep -q HealthSyncSingleton "$MEM"; then status 'HealthSyncSingleton'; echo "  Mutex HealthSyncSingleton-h\$lthb4n3 | -  | $ST"; fi
echo

echo "SUMMARY:"
echo "  Known indicators confirmed: $KNOWN   New indicators discovered: $NEW   Modified: $MOD"
echo "  ATT&CK techniques identified: $(printf '%s\n' "${!TECH[@]}" | sort | paste -sd',' | sed 's/,/, /g')"
grep -qiE 'chain of custody' "$MEM" && echo "  Confidence: HIGH (primary volatile evidence, chain of custody $(grep -m1 -oE 'MD-IR[A-Z0-9-]+' "$MEM"))"
echo
bar
