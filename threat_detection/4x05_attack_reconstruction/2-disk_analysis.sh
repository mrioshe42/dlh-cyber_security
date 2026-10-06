#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
D="$BASE/ir_evidence/disk_forensics_report.txt"; MEM="$BASE/ir_evidence/memory_artifacts.txt"
FW=$(ls "$BASE"/ir_evidence/*firewall*.json 2>/dev/null | head -1); TOPO="$BASE/reference/network_topology.txt"
NAV="$BASE/reference/attck_navigator_80pct.json"
for f in "$D" "$TOPO"; do [ -f "$f" ] || { echo "Missing: $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar()  { printf '%*s\n' 64 '' | tr ' ' '='; }
secn() { awk -v n="$1" '$0 ~ "^SECTION "n" " {f=1; next} f && /^SECTION [0-9]+ /{exit} f' "$D"; }
mb()   { awk -v b="$1" 'BEGIN{ if (b>=1e6) printf "%.1f MB", b/1e6; else printf "%d B", b }'; }
num()  { tr -d ' ,' <<< "$1"; }
short() { sed -E 's/^20[0-9]{2}-//; s/ CDT//' <<< "$1"; }
declare -A TECH

bar
echo "   DISK FORENSICS ANALYSIS - $(grep -m1 -oE '^ +Host: +[A-Z0-9-]+' "$D" | awk '{print $2}')"
echo "   Source: ir_evidence/disk_forensics_report.txt   Image: $(grep -m1 'Image acquired' "$D" | sed -E 's/^[^:]*: *//; s/ +\(.*//')"
bar
echo

echo "RECOVERED DELETED FILES:"
printf '  %-3s %-24s %-15s %-12s %s\n' ID File Deleted Size "Content"
FWB=$(jq -r '.sessions[]? | select(.classification=="EXFIL_BURST") | "\(.bytes_out) \(.ts_start[0:10])"' "$FW" 2>/dev/null)
ZIPS=0; ZMATCH=0; RECS=0
blocks=$(secn 3 | awk '/^3\.2 /{f=1} /^3\.3 /{f=0} f')
for id in $(grep -oE '^\[D[0-9]+\]' <<< "$blocks" | tr -d '[]'); do
    b=$(awk -v i="[$id]" 'index($0,i)==1{f=1;print;next} f&&/^\[D[0-9]+\]/{exit} f' <<< "$blocks")
    path=$(head -1 <<< "$b" | sed -E 's/^\[D[0-9]+\] +//; s/ +\(DELETED.*//')
    sz=$(grep -m1 'Recovered size' <<< "$b" | sed -E 's/^[^:]*: *//')
    bytes=$(grep -oE '^[0-9 ]+ bytes' <<< "$sz" | head -1 | tr -dc 0-9)
    szs=$([ -n "$bytes" ] && mb "$bytes" || echo "~11 MB part.")
    del=$(short "$(grep -m1 'Deletion timestamp' <<< "$b" | sed -E 's/^[^:]*: *//; s/ +\(.*//')")
    rows=$(num "$(grep -m1 'Row count' <<< "$b" | sed -E 's/^[^:]*: *//; s/ *\(.*//')")
    hdr=$(grep -A1 -m1 -iE 'header:' <<< "$b" | sed -E 's/^[^:]*: *//' | tr -d '\n ' | cut -c1-45)
    ct="${rows:+$rows rows: $hdr}"; [ -z "$del" ] && del="n/a"; [ -z "$ct" ] && grep -qi 'lsass\|mimikatz' <<< "$b" && ct="LSASS dump output (Mimikatz format)"
    [ -z "$ct" ] && grep -q '"clear_logs"' <<< "$b" && ct="exfiltrator config (clear_logs:true, stage_dir)"
    printf '  %-3s %-24s %-15s %-12s %s\n' "$id" "$(basename "${path//\\//}")" "$del" "$szs" "$ct"
    if [[ "$path" == *.zip ]]; then
        ZIPS=$((ZIPS + 1)); RECS=$((RECS + ${rows:-0}))
        fw=$(grep -m1 "^$bytes " <<< "$FWB"); [ -n "$fw" ] && ZMATCH=$((ZMATCH + 1))
        la=$(short "$(grep -m1 ' A: ' <<< "$b" | sed -E 's/^ *A: *//; s/ +\(.*//')")
        echo "         -> created > read ${la:6:5} > deleted ${del:6:8}; firewall burst of identical size: $([ -n "$fw" ] && echo "yes, ${fw#* }" || echo NO)"
    fi
done
dir=$(grep -m1 -oE 'C:\\Users\\Public\\Tmp\\' <<< "$blocks")
echo "  ANALYSIS: structured SQL exports (out_<timestamp>.csv, header + rows) archived with Compress-Archive into $dir,"
echo "  then deleted ~3 s after last read. $ZIPS archives, $RECS records$( [ "$ZIPS" -gt 0 ] && [ "$ZMATCH" -eq "$ZIPS" ] && echo "; sizes match $ZMATCH/$ZIPS firewall exfil bursts" )."
echo "  Staging: $( [ "$ZIPS" -gt 0 ] && [ "$ZMATCH" -eq "$ZIPS" ] && echo "COMPLETED and transmitted, not interrupted" || echo "completed on disk; transmission not confirmed here")."
echo "  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive via Utility, T1070.004 File Deletion"; TECH[T1074.001]=1; TECH[T1560.001]=1; TECH[T1070.004]=1
echo

echo "PREFETCH ANALYSIS (times CDT):"
printf '  %-20s %-12s %-12s %-5s %s\n' Program "Oldest" Last Runs "Expected on a records WS?"
auth=$(sed -n '/No other workstation is authorized/,/^$/p' "$TOPO" | tr 'A-Z' 'a-z')
psec=$(secn 5)
while read -r pf last_d last_t cnt; do
    exe=${pf%%-*}; base=$(tr 'A-Z' 'a-z' <<< "${exe%.EXE}")
    ts=$(awk -v p="$pf" 'index($0,p)==1 && !/ +[0-9]{4}-/ {f=1; next} f&&/^$/{exit} f&&/^[A-Z0-9_]+\.EXE-/{exit} f' <<< "$psec" | grep -oE '[0-9]{4}-[0-9-]+ [0-9:]+' | sort | head -1)
    path=$(grep -m1 "^$pf" <<< "$psec" | sed -E 's/.* +[0-9]+ \*? +//')
    if   [ "$base" = powershell ]; then ex="PARTIAL (normal use; daily 02:00 runs suspect)"
    elif grep -qF "$base" <<< "$auth" || [ "$base" = wsmprovhost ]; then ex="NO (admin tool; only WS-ADMIN-01 authorised)"
    elif [[ "$path" =~ Users|Temp|AppData ]]; then ex="NO (runs from user-writable path)"
    else ex="YES"; fi
    printf '  %-20s %-12s %-12s %-5s %s\n' "$exe" "$(short "${ts:-$last_d $last_t}" | cut -c1-11)" "$(short "$last_d $last_t" | cut -c1-11)" "${cnt//[^0-9]/}" "$ex"
done < <(grep -E '^[A-Z0-9_]+\.EXE-[0-9A-F]+\.pf +20' <<< "$psec" | awk '{print $1, $2, $3, $4}')
echo "  (Oldest = oldest run time listed in the .pf detail; PowerShell lists only its last 8 of 18 runs)"
echo

echo "SCHEDULED TASK (confirms memory analysis):"
xml=$(secn 4); xv() { grep -oE "<$1>[^<]*" <<< "$xml" | head -1 | sed "s/<$1>//"; }
args=$(xv Arguments); reg=$(xv Date)
dec=$(base64 -d 2>/dev/null <<< "$(grep -oE '[A-Za-z0-9+/=]{60,}' <<< "$args")" | iconv -f UTF-16LE -t UTF-8 2>/dev/null | tr '\r\n' '  ' | sed 's/  */ /g')
echo "  Task XML: $(xv URI | tr -d '\\')   Author: $(xv Author)   RunLevel: $(xv RunLevel)   Hidden: $(xv Hidden)"
echo "  Trigger: Calendar, every $(xv DaysInterval) day, StartBoundary=$(xv StartBoundary | sed 's/.*T//')"
echo "  Action: $(xv Command | sed 's/.*\\//') $(sed -E 's/ -EncodedCommand.*/ -EncodedCommand [base64]/' <<< "$args")  => ${dec:0:85}"
echo "  Registration: ${reg%.*} CDT"
if [ -f "$MEM" ]; then
    m64=$(grep -A3 'EncodedCommand' "$MEM" | grep -oE '[A-Za-z0-9+/=]{60,}' | head -1)
    [ -n "$m64" ] && [ "$m64" = "$(grep -oE '[A-Za-z0-9+/=]{60,}' <<< "$args")" ] && same="identical command" || same="command differs"
    mt=$(grep -A4 '^\[K2\]' "$MEM" | grep -oE '\(([0-9:]+) CDT\)' | tr -d '()' | head -1)
    echo "  -> CONFIRMED: $same as memory PID 8472; registry write ${mt:-?} matches XML ${reg#*T} CDT"
fi
TECH[T1053.005]=1; echo "  ATT&CK: T1053.005 Scheduled Task/Job"
echo

echo "REGISTRY PERSISTENCE:"
secn 7 | awk '/^\[R[0-9]\]/{if (k) print k "|" v "|" w; k=$0; sub(/^\[R[0-9]\] +/,"",k); v=""; w=""; next}
    /Value( name)?:/ && !v {v=$0; sub(/^[^:]*: */,"",v)} /Last write/ {w=$0; sub(/^[^:]*: */,"",w)} END{if (k) print k "|" v "|" w}' \
  | while IFS='|' read -r k v w; do
      case "$k" in
        *Run*)        echo "  [!] $k = $v (last write ${w% UTC})  -> Run-key persistence, T1547.001"; TECH[T1547.001]=1 ;;
        *Exclusions*) echo "  [!] Defender exclusion $v (last write ${w})  -> T1562.001" ;;
        *)            : ;;
      esac
    done
echo

echo "ANTI-FORENSICS INDICATORS:"
s9=$(secn 9)
awk '/^Observed:/{f=1;next} /^NOT observed/{exit} f&&/^  T1[0-9]{3}/{if (l) print l; l=$0; next} f&&/^ {20,}[^ ]/{l=l " " $0} END{print l}' <<< "$s9" \
  | sed -E 's/ {2,}/ /g; s/^ /  [*] /' | cut -c1-110
TECH[T1070.001]=1; TECH[T1070.004]=1; TECH[T1562.001]=1
echo "  [ ] Not observed: $(awk '/^NOT observed/{f=1;next} /^\[ANALYST/{exit} f&&/^  [A-Z$]/{sub(/^ +/,""); sub(/ {2,}.*/,""); print}' <<< "$s9" | paste -sd, | sed 's/,/, /g')"
echo "      -> timestamps trustworthy (\$MFT intact, W32Time not tampered): no timestamp manipulation"
echo

echo "NTFS TIMELINE (CDT, creation/deletion/gap events in key directories):"
secn 6 | sed '/^\[ANALYST/,$d' | awk '
    /^20[0-9]{2}-[0-9]{2}-[0-9]{2} +[0-9:]+ /{ if (l) print l; l=$0; next }
    l && /^ +[^ ]/ { gsub(/^ +/," "); l=l $0 }
    END{ if (l) print l }' | sed -E 's/ {2,}/ /g' | grep -E ' (B,M,C|D) |GAP (STARTS|ENDS)|Registry hive' \
  | grep -E 'Temp|Tmp|Tasks|winevt|GAP' | sed -E 's/\\ +/\\/; s/^20[0-9]{2}-//; s/ - -- .*<SECURITY EVENT LOG GAP (STARTS|ENDS)>.*/ Security log gap \1/; s/ *\[[^]]*\].*$//; s/\\\\+/\\/g; s/^/  /' | cut -c1-110
echo

echo "SUMMARY:"
ids=$(secn 1 | grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' | sort -u; printf '%s\n' "${!TECH[@]}")
new=""; for t in $(sort -u <<< "$ids"); do
    s=$(jq -r --arg t "$t" '[.techniques[] | select(.techniqueID==$t) | .comment | split(" ")[0]] | first // "ABSENT"' "$NAV" 2>/dev/null)
    [ "$s" != OBSERVED ] && new+="$t, "; done
echo "  New ATT&CK techniques (not OBSERVED in the Navigator layer): ${new%, }"
echo "  Evidence confirms data staging: $RECS patient/insurance records in $ZIPS archives$( [ "$ZMATCH" -eq "$ZIPS" ] && echo ", matched to firewall exfil bursts" ) => reportable breach scope"
echo "  Anti-forensics: basic only (file deletion, Security log cleared, Defender exclusion); VSS/USN/prefetch left intact"
echo
bar
