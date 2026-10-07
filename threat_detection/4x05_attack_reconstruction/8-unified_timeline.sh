#!/bin/bash

export LC_ALL=C
HERE="$(dirname "$(readlink -f "$0")")"; BASE="${1:-$HERE/4x05}"
P="$BASE/previous_findings"; I="$BASE/ir_evidence"
f00=$(ls "$P"/4x00*.txt); f01=$(ls "$P"/4x01*.txt); f03=$(ls "$P"/4x03*.txt); H=$(ls "$P"/4x04*.txt)
MEM=$(ls "$I"/memory*.txt); DISK=$(ls "$I"/disk*.txt); FW=$(ls "$I"/firewall*.json); NOTES="$I/ir_team_notes.txt"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
YEAR=$(grep -m1 -oE '20[0-9]{2}' "$f00" | head -1); SKEW=$(jq -r '.metadata._notes | join(" ")' "$FW" | grep -oE 'are [0-9]+ seconds' | grep -oE '[0-9]+'); SKEW=${SKEW:-4}

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
ep()  { date -u -d "$1" +%s; }
z()   { date -u -d "@$1" +'%m-%d %H:%M:%SZ'; }
lc()  { date -u -d "@$(( $1 - 18000 ))" +'%m-%d %H:%M'; }
dur() { awk -v s="$1" 'BEGIN{ if (s<0) s=-s; if (s<120) printf "%ds", s; else if (s<7200) printf "%dm%02ds", s/60, s%60; else if (s<172800) printf "%dh%02dm", s/3600, (s%3600)/60; else printf "%.1f days", s/86400 }'; }

declare -a OUT
run() { [ -x "$HERE/$1" ] && "$HERE/$1" "$BASE" 2>/dev/null; }
parse() {
    awk -v lab="$1" -v dtz="$2" '
    function flush() { if (ts != "") print lab "\t" ts "\t" tz "\t" desc "\t" body; ts = "" }
    /^  \[[0-9][0-9]-[0-9][0-9] [0-9:]+(Z| CDT)?\]/ { flush(); match($0, /\[[^]]*\]/); st = substr($0, RSTART + 1, RLENGTH - 2); desc = substr($0, RSTART + RLENGTH + 1)
        n = split(st, a, " "); ts = a[1] " " a[2]; tz = dtz; if (a[2] ~ /Z$/) { tz = "Z"; sub(/Z$/, "", a[2]); ts = a[1] " " a[2] } else if (a[3] == "CDT") tz = "CDT"; body = ""; next }
    ts != "" && /^$/ { flush(); next }
    ts != "" && /^[A-Z]/ { flush(); next }
    ts != "" && /^  [A-Za-z]/ { flush(); next }
    ts != "" { gsub(/^ +/, ""); body = body " " $0 }
    END { flush() }'
}
T5=$(run 5-stages_1_2.sh | parse S12 Z); T7=$(run 7-stage_4.sh | parse S4 CDT); T6=$(run 6-stage_3.sh | parse S3 CDT)
HAVE6=$([ -n "$T6" ] && echo yes || echo no)

declare -A FWTS; while read -r t; do [ -n "$t" ] && FWTS[$(ep "$t")]=1; done < <(jq -r '(.sessions[]? | select(.session_id) | .ts_start), (.summary.by_classification[]? | .first_seen_in_window? // empty), (.summary.by_classification[]? | .last_seen_in_window? // empty | split(" ")[0])' "$FW")

ROWS=()
add() {
    ROWS+=("$1|$2|$3|$4|$5|$6|$7|$8|$9")
}
srcs_of() { { grep -q 'absent from 4x01' <<< "$1" && sed 's/4x01//g' <<< "$1" || echo "$1"; } | grep -oE '4x0[0-4]|IR-MEM|IR-DISK|IR-FW|IR note|\b(MEM|DISK|FW)\b' <<< "$1" | sed 's/IR-//; s/IR note/NOTES/' | sort -u | paste -sd,; }
host_of() { local h; h=$(grep -oE '(WS|SRV)-[A-Z]+-[A-Z0-9]+' <<< "$1" | sed -E 's/^(WS|SRV)-//' | awk '!s[$0]++' | paste -sd'>')
            if [ -z "$h" ]; then
                if grep -qiE 'installed|written|born|Last exfiltrator' <<< "$1"; then h="RECV-03"
                elif grep -qiE 'mail|campaign|phish|lookalike' <<< "$1"; then h="ext>RECV-03"
                elif grep -qiE 'beacon|C2|exfiltration|POST' <<< "$1"; then h="RECV-03>C2"
                else h="-"; fi
            elif [[ "$h" != *">"* ]] && grep -qiE 'sent to 185|beacon|exfiltration:' <<< "$1"; then h="$h>C2"; fi
            echo "$h"; }
cred_of() { grep -oE 'svc_[a-z]+|records03|dmarsh' <<< "$1" | awk '!s[$0]++' | paste -sd, ; }
ingest() {
    while IFS=$'\t' read -r lab ts tz desc body; do
        [ -z "$ts" ] && continue
        local e; if [ "$tz" = Z ]; then e=$(ep "$YEAR-${ts% *} ${ts#* } UTC"); else e=$(( $(ep "$YEAR-${ts% *} ${ts#* } UTC") + 18000 )); fi
        local adj=""; [ -n "${FWTS[$e]}" ] && [[ "$desc" == "C2 pattern"* || "$desc" == "Secondary C2 first seen"* ]] && { e=$((e - SKEW)); adj="*"; }
        [[ "$ts" == *" 00:00:00" ]] && adj="${adj}date only"
        local all="$desc $body"; local techs; techs=$(grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' <<< "$all" | awk '!s[$0]++' | paste -sd,)
        local conf; conf=$(grep -oE 'CONFIRMED|PROBABLE|POSSIBLE' <<< "$all" | head -1)
        local src; src=$(srcs_of "$all"); local ns; ns=$(tr ',' '\n' <<< "$src" | grep -vc '^NOTES$' )
        local note; note=$(grep -oE '\| [^|]*(off the prefetch|disputed|unexplained|inference|how it returned)[^|]*' <<< "$all" | head -1 | sed 's/^| //')
        [[ "$desc" == *"isolated"* ]] && lab=C
        add "$e" "$lab" "$(sed -E 's/ \([0-9]+ sources\).*//; s/;.*$//; s/: IR-.*$//; s/\):.*$/)/; s/ via \$\{.*//' <<< "$desc" | cut -c1-200)" "$(host_of "$desc")" "$(cred_of "$all")" "$techs" "${conf:-?}:$ns" "$src" "$adj$note"
        if grep -qE 'Then: ' <<< "$body"; then
            local zt dt ut mbv; zt=$(grep -oE 'Then: zip [0-9:]{8}' <<< "$body" | grep -oE '[0-9:]{8}'); dt=$(grep -oE 'deleted [0-9:]{8}' <<< "$body" | grep -oE '[0-9:]{8}')
            ut=$(grep -oE ' at [0-9:]{8} ' <<< "$body" | grep -oE '[0-9:]{8}'); mbv=$(grep -oE '[0-9.]+ MB sent' <<< "$body" | grep -oE '^[0-9.]+')
            local d0=${ts% *}; local conv="CONFIRMED:2"
            [ -n "$zt" ] && add "$(( $(ep "$YEAR-$d0 $zt UTC") + 18000 ))" "$lab" "Archive staged: Compress-Archive -> Public\\Tmp\\*.zip" "RECV-03" "records03" "T1560.001,T1074.001" "$conv" "DISK" ""
            if [ -n "$ut" ]; then ue=$(( $(ep "$YEAR-$d0 $ut UTC") + 18000 - SKEW )); dd=$(( $(ep "$YEAR-$d0 $dt UTC") + 18000 )); un=""; (( ue + SKEW - dd <= 2 * SKEW && ue + SKEW - dd >= -2 * SKEW )) && un="unprovable order of file deletion vs upload ($(( ue + SKEW - dd )) s apart, firewall skew ${SKEW} s)"
                add "$ue" "$lab" "Exfiltration: ${mbv} MB POST to C2, file deleted (${dt:-n/a})" "RECV-03>C2" "records03" "T1041,T1070.004" "$conv" "DISK,FW" "*$un"; fi
        fi
    done
}
ingest <<< "$T5"; ingest <<< "$T7"; [ "$HAVE6" = yes ] && ingest <<< "$T6"

if [ "$HAVE6" = no ]; then
    avd=$(grep -A1 'AV detection on' "$f03" | grep -m1 -oE '20[0-9]{2}-[0-9-]+')
    [ -n "$avd" ] && add "$(ep "$avd 12:00 UTC")" S3 "S2 detected by AV and quarantined on WS-RECV-03 (date only)" "RECV-03" "-" "-" "POSSIBLE:1" "4x03" "date only, time unknown"
    f5=$(awk '/sync_healthdata.ps1$/{f=1} f&&/ B: /{print;exit}' "$DISK" | grep -oE '20[0-9-]+ [0-9:]{8}'); f5d=$(grep -m1 -oE 'First observed: +20[0-9-]+' "$f03" | tail -1)
    [ -n "$f5" ] && add "$(( $(ep "$f5 UTC") + 18000 ))" S3 "S3 exfiltrator sync_healthdata.ps1 written on WS-RECV-03 (C2 beacon response, 1.4 KB)" "C2>RECV-03" "records03" "T1105" "CONFIRMED:2" "4x03,DISK" ""
    st1=$(grep -E '^20[0-9-]+ +[0-9:]+ +B,M,C .*stage1' "$DISK" | head -1 | awk '{print $1" "$2}')
    [ -n "$st1" ] && add "$(( $(ep "$st1 UTC") + 18000 ))" S3 "S3 copied to SRV-HEALTH-DB as stage1.ps1 (Net-Use / Copy-Item over PSRemoting)" "RECV-03>HEALTH-DB" "svc_healthsync" "T1570,T1021.006" "CONFIRMED:2" "4x04,DISK" ""
fi
iso=$(grep -m1 'ENTRY #001' "$NOTES" | grep -oE '20[0-9-]+ +[0-9:]+ CDT' | sed -E 's/ +/ /; s/ CDT//')
auth=$(grep -m1 -oE 'authorized isolation at [0-9:]+ CDT' "$NOTES" | grep -oE '[0-9:]+')
ISO=$(( $(ep "$iso UTC") + 18000 ))
[ -n "$auth" ] && add "$(( $(ep "${iso%% *} $auth UTC") + 18000 ))" C "Hunt findings (4x04 R1) escalated; isolation authorised by CISO" "-" "-" "-" "PROBABLE:1" "NOTES,4x04" "hunt detection time itself is undated"
esc=$(grep -m1 'IR escalation issued' "$H" | grep -oE '20[0-9-]+ [0-9:]+' | head -1)
[ -n "$esc" ] && add "$(( $(ep "$esc UTC") + 18000 ))" C "4x04 report records 'IR escalation issued' (dated AFTER the isolation)" "-" "-" "-" "POSSIBLE:1" "4x04" "out of order: see sequencing uncertainties"

mapfile -t SORTED < <(printf '%s\n' "${ROWS[@]}" | sort -t'|' -k1,1n -s)
declare -A SEEN; UNI=()
for r in "${SORTED[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; key="$e|${t%%,*}|${d:0:24}"; [ -n "${SEEN[$key]}" ] && continue; SEEN[$key]=1; UNI+=("$r"); done

FIN=(); for r in "${UNI[@]}"; do IFS='|' read -r e st d _ <<< "$r"; [[ "$d" == *"Memory captured"* ]] && continue; FIN+=("$r"); done

N=${#FIN[@]}; first=${FIN[0]%%|*}; for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; [[ "$t" == *T1566* ]] && { first=$e; break; }; done
tag() { local c=${1%%:*} n=${1##*:}; if [ "$c" = "?" ]; then c=; fi
        if [ "$n" -ge 2 ]; then echo CONV; elif [ "$c" = POSSIBLE ]; then echo POSS; elif [ "$c" = PROBABLE ]; then echo PROB; else echo SING; fi; }
bar
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Period: $(z "$first") to $(z "$ISO") containment ($YEAR; UTC, CDT = UTC-5; * = firewall time minus ${SKEW} s)"
bar
echo
echo "CHRONOLOGICAL SEQUENCE:  (S: stage; Conf: CONV = 2+ independent sources, SING = 1, PROB/POSS = inference)"
printf '  %-3s %-3s %-17s %-52s %-17s %-14s %-19s %-5s %s\n' '#' S 'Time (UTC)' Event 'Host(s)' 'User/cred' 'ATT&CK' Conf Sources
i=0; NC=0; NS=0
for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; i=$((i + 1)); k=$(tag "$cf"); [ "$k" = CONV ] && NC=$((NC + 1)); [ "$k" = SING ] && NS=$((NS + 1))
    printf '  %02d  %-3s %-17s %-52.52s %-17.17s %-14.14s %-19.19s %-5s %s\n' "$i" "${st/S12/1-2}" "$(z "$e")$([[ "$n" == \** ]] && echo '*')" "$d" "$h" "${c:--}" "${t:--}" "$k" "${s:--}"; done
echo
echo "  Total events: $N | CONVERGED: $NC ($(( NC * 100 / N ))%) | SINGLE-SOURCE: $NS ($(( NS * 100 / N ))%) | inference (PROB/POSS): $(( N - NC - NS ))"
[ "$HAVE6" = no ] && echo "  Note: 6-stage_3.sh is not present; Stage 3 events were taken from the raw evidence (4x03, 4x04, disk)."
echo

find_e() { for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; [[ ",$t," == *",$1,"* ]] && { echo "$e"; return; }; done; }
cred=$(find_e T1078); foot=$(find_e T1105); lat=$(find_e T1021.002); task=$(find_e T1053.005); run=$(find_e T1547.001); stg=$(find_e T1005)
echo "TEMPORAL METRICS:"
echo "  Total dwell time:         $(dur $(( ISO - cred ))) from first compromise ($(z "$cred") credential theft); $(dur $(( ISO - foot ))) from the RAT foothold ($(z "$foot"))"
echo "  Breakout time:            $(dur $(( lat - foot ))) ($(( (lat - foot) / 3600 )) h) from the RAT foothold to the first lateral move ($(z "$lat")); $(dur $(( lat - cred ))) from the credential theft"
echo "  Time to persistence:      Run-key $(dur $(( run - foot ))) after foothold (reinstall at $(z "$run"); first install undated); scheduled task $(dur $(( task - foot )))"
echo "  Time to data staging:     $(dur $(( stg - foot ))) from foothold to the first staging file ($(z "$stg"))"
hs=$(grep -m1 'Hunt window' "$H" | grep -oE '20[0-9-]+' | head -1)
echo "  Detection to containment: authorisation $(dur $(( ISO - $(ep "${iso%% *} ${auth} UTC") - 18000 ))) before isolation; hunt start -> containment is NOT computable: 4x04 dates the hunt/escalation ${esc%% *} (3 days AFTER isolation)"

M=(); for key in T1105 T1562.001 T1003.001 T1021.002 T1053.005 T1005 T1041; do v=$(find_e "$key"); [ -n "$v" ] && M+=("$v"); done
sorted=($(printf '%s\n' "${M[@]}" | sort -n)); sg=0; for ((k = 1; k < ${#sorted[@]}; k++)); do sg=$(( sg + sorted[k] - sorted[k-1] )); done
act=0; night=0; days=""; for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; [ "$e" -lt "$lat" ] && [ "$e" -lt "$(find_e T1562.001)" ] && continue; [ "$e" -gt "$ISO" ] && continue
    [ "${st}" = C ] && continue; hh=$(( (e - 18000) % 86400 / 3600 )); act=$((act + 1)); ((hh >= 1 && hh < 4)) && night=$((night + 1)); days+="$(lc "$e" | cut -c1-5) "; done
echo "  Operational tempo:        milestones every $(dur $(( sg / (${#sorted[@]} - 1) ))) on average; $night of $act post-05-04 events fall at 01:00-04:00 CDT; active nights: $(tr ' ' '\n' <<< "$days" | awk 'NF&&!s[$0]++' | paste -sd' ')"
echo

echo "TIMELINE GAPS:"
cov() { echo "$1|$(ep "$2 UTC")|$(( $(ep "$3 UTC") + 86399 ))"; }
pc=$(grep -m1 'PCAP collection window' "$f01" | grep -oE '20[0-9-]+' | paste -sd' '); us=$(grep -m1 'USN journal range' "$DISK" | grep -oE '20[0-9-]+' | paste -sd' ')
fr=$(jq -r '.metadata.time_range_utc | "\(.start[0:10]) \(.end[0:10])"' "$FW"); hw=$(grep -m1 'Hunt window' "$H" | grep -oE '20[0-9-]+' | paste -sd' ')
COV=( "$(cov PCAP $pc)" "$(cov DISK-USN $us)" "$(cov FW $fr)" "$(cov SIEM $hw)" )
g=0; prev=; for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; { [ "$st" = C ] || [ "$e" -lt "$first" ]; } && continue
    if [ -n "$prev" ] && [ $(( e - prev )) -ge 172800 ]; then
        g=$((g + 1)); hrs=0; cov=0; who=""
        for ((x = prev; x < e; x += 3600)); do hrs=$((hrs + 1)); hit=0; for cv in "${COV[@]}"; do IFS='|' read -r nm a2 b2 <<< "$cv"; (( a2 <= x && b2 >= x )) && { hit=1; [[ " $who " == *" $nm "* ]] || who+="$nm "; }; done; cov=$((cov + hit)); done
        pct=$(( cov * 100 / hrs )); who=${who% }
        if [ "$pct" -lt 25 ]; then asm="COLLECTION GAP (${pct}% covered${who:+ by $who}); attacker activity unknown, C2 beaconing presumed"
        elif [ "$who" = FW ]; then asm="single source only (firewall, ${pct}% covered): beaconing visible, no host view"
        else asm="covered ${pct}% by ${who// /+} yet no hands-on activity found: dormant/beacon-only or low-and-slow"; fi
        echo "  GAP $g: $(z "$prev" | cut -c1-5) to $(z "$e" | cut -c1-5) ($(dur $(( e - prev )))) -- $asm"; fi
    prev=$e; done
echo "  Standing blind spots: no network capture $(cut -c6-10 <<< "$(date -u -d "$(cut -d' ' -f2 <<< "$pc") +1 day" +%F)") -> $(cut -c6-10 <<< "${fr%% *}"); no host telemetry before $(awk '{print $1}' <<< "${us}" | cut -c6-); SIEM only from $(cut -d' ' -f1 <<< "$hw" | cut -c6-)."
echo

echo "SEQUENCING UNCERTAINTIES:"
pe=0; pd=; ps=; k=0
for r in "${FIN[@]}"; do IFS='|' read -r e st d h c t cf s n <<< "$r"; k=$((k + 1))
    if [ "$pe" -gt 0 ] && [ $(( e - pe )) -le $(( 2 * SKEW )) ] && [ "$ps" != "$s" ]; then echo "  [*] Events $((k-1)) and $k are $(dur $(( e - pe ))) apart from different sources (firewall skew $SKEW s): order not provable. Impact: minimal."; fi
    [[ "$n" == *"date only"* ]] && echo "  [*] Event $k ('${d:0:40}'): date only, no time. Impact: minimal."
    [[ "$n" == *"undated"* || "$n" == *"out of order"* ]] && echo "  [*] Event $k ('${d:0:44}'): $n. Impact: significant for the detection->containment metric."
    [[ "$n" == *"off the prefetch"* ]] && echo "  [*] Event $k ('${d:0:36}'): $n. Impact: minimal (prefetch+firewall adopted)."
    [[ "$n" == *"unprovable order"* ]] && echo "  [*] Event $k ('${d:0:30}'): ${n#\*}. Impact: minimal." 
    [[ "$n" == *"disputed"* ]] && echo "  [*] Event $k ('${d:0:36}'): attribution disputed (R. Kim vs attacker); timing is solid. Impact: minimal."
    [[ "$n" == *"how it returned"* || "$n" == *"unexplained"* ]] && echo "  [*] Event $k ('${d:0:36}'): $n. Impact: significant: S2 delivered 04-15 but re-created 04-22."
    pe=$e; ps=$s; done | sort -u
echo "  [*] Delivery date of the RAT (04-15, network) vs file birth (04-22, disk) is only reconciled by inference (AV quarantine 04-21 + reinstall at reboot)."
echo
bar
