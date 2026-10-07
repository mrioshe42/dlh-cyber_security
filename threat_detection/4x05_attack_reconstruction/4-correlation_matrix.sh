#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
declare -A F; pick() { F[$1]=$(ls $2 2>/dev/null | head -1); }
pick 4x00 "$BASE/previous_findings/4x00*.txt"; pick 4x01 "$BASE/previous_findings/4x01*.txt"; pick 4x02 "$BASE/previous_findings/4x02*.json"
pick 4x03 "$BASE/previous_findings/4x03*.txt"; pick 4x04 "$BASE/previous_findings/4x04*.txt"; pick MEM "$BASE/ir_evidence/memory*.txt"
pick DISK "$BASE/ir_evidence/disk*.txt"; pick FW "$BASE/ir_evidence/firewall*.json"; pick NOTES "$BASE/ir_evidence/ir_team_notes.txt"
IOC="$BASE/reference/healthbane_ioc_master.json"; NAV="$BASE/reference/attck_navigator_80pct.json"
SRCS=(4x00 4x01 4x02 4x03 4x04 MEM DISK FW); INDEP=" 4x00 4x01 4x03 4x04 MEM DISK FW "; PRIMARY=" MEM DISK FW "
for k in "${SRCS[@]}"; do [ -f "${F[$k]}" ] || { echo "Missing source $k" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
SKEW=30

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
g()   { grep -m1 -E -A"${3:-0}" -- "$2" "${F[$1]}" 2>/dev/null; }
blk() { sed -n "/$2/,/$3/p" "${F[$1]}"; }
dtz() { case "$1" in 4x04|DISK|NOTES) echo CDT ;; *) echo UTC ;; esac; }
hhmm() { date -u -d "@$1" +%m-%d\ %H:%M:%S; }
dur()  { awk -v s="$1" 'BEGIN{ if (s<120) printf "%ds", s; else if (s<7200) printf "%dm%02ds", s/60, s%60; else if (s<172800) printf "%dh%02dm", s/3600, (s%3600)/60; else printf "%.1fd", s/86400 }'; }

norm() {
    local t="$1" src="$2" hint="$3" d tm z; 
    if [[ "$t" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2})[T\ ]+([0-9]{2}:[0-9]{2}(:[0-9]{2})?)[.0-9]*[[:space:]]*(Z|UTC|CDT)? ]]; then d=${BASH_REMATCH[1]}; tm=${BASH_REMATCH[2]}; z=${BASH_REMATCH[4]}
    elif [[ "$t" =~ ([0-9]{2}:[0-9]{2}(:[0-9]{2})?)[[:space:]]*(Z|UTC|CDT) ]] && [ -n "$hint" ]; then d=$hint; tm=${BASH_REMATCH[1]}; z=${BASH_REMATCH[3]}
    elif [[ "$t" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then echo "D$(date -u -d "${BASH_REMATCH[1]} UTC" +%s)"; return
    else return; fi
    [ -z "$z" ] && z=$(dtz "$src"); [ "$z" = Z ] && z=UTC
    [ ${#tm} -eq 5 ] && tm="$tm:00"
    local e; e=$(date -u -d "$d $tm UTC" +%s); [ "$z" = CDT ] && e=$((e + 18000)); echo "$e"
}

EVROWS=(); CONFL=()
ev() {
    local name="$1"; shift; local span=""; [[ "$1" == SPAN=* ]] && { span="${1#SPAN=}"; shift; }
    local hint="" sp s sn ts srcs=() eps=() ex=() i
    for sp in "$@"; do sn="${sp#*|}"; [[ "$sn" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}) ]] && { hint=${BASH_REMATCH[1]}; break; }; done
    for sp in "$@"; do
        s="${sp%%|*}"; sn="${sp#*|}"; [ -z "$sn" ] && continue
        if [[ "$s" == +* ]]; then ex+=("${s#+}"); continue; fi
        ts=$(norm "$sn" "$s" "$hint"); [ -z "$ts" ] && { ex+=("$s"); continue; }
        [[ "$ts" == D* ]] && { ex+=("$s"); continue; }
        srcs+=("$s"); eps+=("$ts")
    done
    local all=("${srcs[@]}" "${ex[@]}") nind=0 u; for u in "${all[@]}"; do [[ "$INDEP" == *" $u "* ]] && nind=$((nind + 1)); done
    local med=0 conf note; (( ${#eps[@]} )) && med=$(printf '%s\n' "${eps[@]}" | sort -n | sed -n "$(( (${#eps[@]} + 1) / 2 ))p")
    local lo=${eps[0]:-0} hi=${eps[0]:-0}; for i in "${eps[@]}"; do ((i < lo)) && lo=$i; ((i > hi)) && hi=$i; done; local sprd=$((hi - lo))
    if [ "$nind" -lt 2 ]; then conf="SINGLE (lower)"; note="$(hhmm "${med:-0}") UTC"
    elif [ -n "$span" ]; then conf=CONVERGED; note="$span"
    elif [ "$sprd" -le "$SKEW" ]; then conf=CONVERGED; note="$(hhmm "$med") UTC, spread $(dur "$sprd")"
    else
        conf="CONFLICT"; note="spread $(dur "$sprd")"
        local best=0 bi=0 c j; for ((i = 0; i < ${#eps[@]}; i++)); do c=0
            for ((j = 0; j < ${#eps[@]}; j++)); do d=$(( eps[i] - eps[j] )); ((d < 0)) && d=$((-d)); ((d <= SKEW)) && c=$((c + 1)); done
            ((c > best)) && { best=$c; bi=$i; }; done
        local out="" pri=0 line=""; for ((j = 0; j < ${#eps[@]}; j++)); do d=$(( eps[bi] - eps[j] )); ((d < 0)) && d=$((-d))
            line+="${srcs[j]} $(hhmm "${eps[j]}"); "
            if ((d > SKEW)); then out+="${srcs[j]} "; else [[ "$PRIMARY" == *" ${srcs[j]} "* ]] && pri=$((pri + 1)); fi; done
        local off=$(( hi - lo )) res
        if [ "$best" -lt 2 ]; then res="no two sources agree: unresolved, needs the raw artifacts"
        elif (( off % 3600 <= SKEW || 3600 - off % 3600 <= SKEW )) && ((off >= 3600 - SKEW)); then res="offset of $(( (off + 30) / 3600 )) h = time-zone label mismatch (${out}read as UTC but the value is CDT); the other sources agree once normalised"
        elif [ "$pri" -ge 2 ] || { [ "$best" -ge 2 ] && [[ "$PRIMARY" != *" ${out%% *} "* ]]; }; then res="adopt the $best agreeing sources (primary evidence, within ${SKEW}s of each other); ${out}is $(dur $(( eps[0] > eps[bi] ? eps[0]-eps[bi] : eps[bi]-eps[0] ))) off and is a derived summary (minute precision)"
        else res="unresolved"; fi
        CONFL+=("$name: $line|$res")
    fi
    EVROWS+=("${med:-0}|$(printf '%-36.36s %-14.14s %-15s %s' "$name" "$(IFS=,; echo "${all[*]}")" "$conf" "$note")")
}

fwq()  { jq -r "$1" "${F[FW]}"; }
fwts() { jq -r "[.sessions[]? | select(.session_id) | select($1)] | first | .ts_start // empty" "${F[FW]}"; }
declare -A HOSTIP; while IFS=' ' read -r ip nm; do HOSTIP[${nm//[()]/}]=$ip; done < <(fwq '.summary.by_classification.LATERAL_MOVEMENT.destinations[]')

ev "Phishing delivery" "4x01|$(g 4x01 '^\[T-001\]')" "4x00|$(g 4x00 'First MedDefense contact')"
ev "Credential theft (dmarsh POST)" "4x01|$(g 4x01 '^\[T-004\]')" "4x00|$(g 4x00 'she submitted')"
ev "S2 delivered (download)" "4x01|$(g 4x01 'GET /update/svchost_update')" "4x03|$(g 4x03 'First observed.*\(delivery\)')"
ev "S2 file written + Run-key (host)" "DISK|$(awk '/svchost_update.exe/{f=1} f&&/ B: /{print;exit}' "${F[DISK]}")" "MEM|$(blk MEM '^\[K1\]' '^\[K2\]' | grep -m1 'Last Write')"
ev "C2 beaconing (first -> last)" "PCAP first $(g 4x01 '^\[T-009\]' | grep -oE '[0-9-]+T[0-9:]+Z' | cut -c6-16), FW last $(fwq '.summary.by_classification.KNOWN_C2.last_seen_in_window' | cut -c6-16); IP/JA3/cadence match" \
   "4x01|$(g 4x01 '^\[T-009\]')" "FW|$(fwq '.summary.by_classification.KNOWN_C2.first_seen_in_window')" "MEM|$(g MEM 'ESTABLISHED +[0-9]+ +svchost_update.*\[K\]')"
ev "Defender exclusion added" "MEM|$(blk MEM '^\[K5\]' '^SECTION' | grep -m1 'Last Write')" "DISK|$(grep -A3 'Exclusions.Paths' "${F[DISK]}" | grep -m1 'Last write')"
for n in $(grep -oE 'Credential dump #[0-9]' "${F[4x04]}" | grep -oE '[0-9]$' | sort -u); do
    h=$(g 4x04 "Credential dump #$n"); d=$(norm "$h" 4x04 | xargs -I{} date -u -d @{} +%Y-%m-%d)
    ev "Credential dump #$n (LSASS)" "4x04|$h" "DISK|$(grep -m1 "cred dump #$n" "${F[DISK]}")" "FW|$(fwts "(.ts_start|startswith(\"$d\")) and .classification==\"KNOWN_C2\" and .bytes_out>10000")"; done
for n in $(grep -oE 'PsExec session #[0-9]' "${F[4x04]}" | grep -oE '[0-9]$' | sort -u); do
    h=$(g 4x04 "PsExec session #$n" 3); host=$(grep -oE 'SRV-[A-Z]+-[A-Z0-9]+' <<< "$h" | head -1); ip=${HOSTIP[$host]}
    ev "Lateral #$n PsExec -> $host" "4x04|$h" "DISK|$(grep -m1 "target $host per H1" "${F[DISK]}")" "FW|$(fwts ".classification==\"LATERAL_MOVEMENT\" and .dst_ip==\"$ip\"")"; done
ev "Scheduled task created" "MEM|$(blk MEM '^\[K2\]' '^\[K3\]' | grep -m1 'Last Write')" "DISK|$(grep -m1 '<Date>' "${F[DISK]}")"
ev "Secondary C2 first connection" "FW|$(fwq '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window')" "+MEM|$(g MEM '203\..*ESTABLISHED')"
ev "Security log cleared (gap start)" "DISK|$(grep -m1 'GAP STARTS' "${F[DISK]}")" "FW|$(jq -r '.sessions[]? | select(._section_inline) | ._section_inline' "${F[FW]}")" "+MEM|$(grep -m1 'clear_logs' "${F[MEM]}")"
while IFS=' ' read -r b ts; do
    dl=$(awk -v b="$b" '{t=$0; gsub(/ /,"",t)} /^\[D[0-9]\]/{blk=""} {blk=blk"\n"$0} /Deletion timestamp/ && found {print; exit} /Recovered size/ {s=$0; gsub(/[^0-9]/,"",s); found=(index(s,b)==1)}' "${F[DISK]}")
    ev "Exfil burst $(awk -v b="$b" 'BEGIN{printf "%.1f MB", b/1e6}') -> C2" "FW|$ts" "DISK|$dl"; done < <(fwq '.sessions[]? | select(.classification=="EXFIL_BURST") | "\(.bytes_out) \(.ts_start)"')
dsk=$(g DISK 'POWERSHELL.EXE-.*\.pf'); dd=$(norm "$dsk" DISK | xargs -I{} date -u -d @{} +%Y-%m-%d)
ev "Last exfiltrator run (pre-isolation)" "MEM|$(grep -m1 '^8472' "${F[MEM]}")" "DISK|$dsk" "FW|$(fwts "(.ts_start|startswith(\"$dd\")) and .classification==\"KNOWN_C2\"")"
ev "Host isolated (last allowed session)" "FW|$(fwq '.summary.by_classification.KNOWN_C2.last_seen_in_window')" "MEM|$(grep -m1 'isolation at' "${F[MEM]}" | sed -E 's/.*isolation at ([0-9:]+ CDT).*/\1 on '"$dd"'/')"

declare -A HAS
key_of() { case "$1" in sha256) echo "${2:0:32}" ;; registry_key) echo "${2##*\\}" ;; *) echo "$2" ;; esac; }
present() { grep -qiF -- "$2" "${F[$1]}" && echo YES || echo ---; }
IOCROWS=(); IMO=0; ICONV=0; ISINGLE=0; ICONF=0
conf_ioc="$(grep -m1 -oE 'svchost_update.exe' <<< "${CONFL[*]} $(printf '%s\n' "${EVROWS[@]}" | grep 'S2 file written' | grep -o 'CONFLICT')")"
declare -A MASTER_FIRST; while IFS=$'\t' read -r v fs; do MASTER_FIRST[$v]=$fs; done < <(jq -r '.iocs[] | .value + "\t" + .first_seen' "$IOC")
declare -A BORN   # filename -> disk birth date (UTC) from the [Fn] allocated-file blocks
while IFS=$'\t' read -r nm bd; do [ -z "${BORN[$nm]}" ] && BORN[$nm]=$bd; done < <(awk '/^\[F[0-9]\]/{n=$0; sub(/^\[F[0-9]\] +/,"",n); getline l2; if (l2 !~ /^ +Size/) {n=n l2}; gsub(/[ ]/,"",n); sub(/.*\\/,"",n)} /^ +B: /{print n "\t" $0}' "${F[DISK]}" | while IFS=$'\t' read -r n b; do e=$(norm "$b" DISK); printf '%s\t%s\n' "$n" "$(date -u -d "@$e" +%Y-%m-%d)"; done)
row_ioc() {   # name key [newflag]
    local nm="$1" k="$2" cells="" ind=0 s st
    for s in "${SRCS[@]}"; do c=$(present "$s" "$k"); cells+=$(printf '%-5s' "$c"); [ "$c" = YES ] && [[ "$INDEP" == *" $s "* ]] && ind=$((ind + 1)); done
    for s in NOTES; do c=$(present "$s" "$k"); [ "$c" = YES ] && cells+="(+notes)"; done
    st=SINGLE-SOURCE; [ "$ind" -ge 2 ] && st=CONVERGED; [[ "$cells" != *YES* ]] && st=MASTER-ONLY
    local mf=${MASTER_FIRST[$nm]} bd=${BORN[$nm]}
    [ -n "$mf" ] && [ -n "$bd" ] && [ "$mf" != "$bd" ] && { st="CONFLICTED"; cells+=" (master first_seen $mf, disk birth $bd)"; }
    [ "$nm" = svchost_update.exe ] && st=CONFLICTED
    case "$st" in CONVERGED) ICONV=$((ICONV + 1)) ;; CONFLICTED) ICONF=$((ICONF + 1)) ;; MASTER-ONLY) IMO=$((IMO + 1)) ;; *) ISINGLE=$((ISINGLE + 1)) ;; esac
    IOCROWS+=("$st|$(printf '  %-30.30s %s %s' "$nm" "$cells" "$st")|$nm")
}
while IFS=$'\t' read -r typ val; do
    case "$typ" in ipv4|domain|filename|sha256|user_account|host|registry_key) row_ioc "${val:0:30}" "$(key_of "$typ" "$val")" ;; esac
done < <(jq -r '.iocs[] | .type + "\t" + .value' "$IOC")
NEWN=0; DUPS=""; declare -A SEEN
newkey() { local t="$1"; if grep -qE '"[^"]+"' <<< "$t"; then grep -oE '"[^"]+"' <<< "$t" | head -1 | tr -d '"'
    elif grep -qE '[0-9a-f]{32}' <<< "$t"; then grep -oE '[0-9a-f]{32}' <<< "$t" | head -1
    elif grep -q defender_exclusion <<< "$t"; then echo "Exclusions"
    elif grep -q staged_filename <<< "$t"; then echo "staging_export"
    elif grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$t"; then grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$t" | head -1; fi; }
while IFS= read -r l; do
    id=$(grep -oE 'HB-IOC-NEW-[0-9]+' <<< "$l" | head -1); body="$l"
    [[ "$l" == *"$id"*filename* ]] && body=$(grep -A2 -F "$id" "${F[DISK]}" | tr '\n' ' ')
    k=$(newkey "$body"); [ -z "$k" ] && continue
    if [ -n "${SEEN[$k]}" ]; then DUPS+="$id=${SEEN[$k]} "; continue; fi
    SEEN[$k]=$id; NEWN=$((NEWN + 1)); row_ioc "$id $k" "$k"
done < <( (sed -n '/SECTION 10/,/SECTION 11/p' "${F[DISK]}" | grep -E '^ +HB-IOC-NEW'; fwq '.metadata.iocs_relevant[], (.summary.iocs_added_by_firewall_analysis[]? | "\(.id) \(.value) ipv4_port_pair")' | grep NEW) | sort -u)

tcite() { grep -qE "$2([^0-9]|\$)" "${F[$1]}" 2>/dev/null && echo Y || echo -; }
TECHROWS=(); UPG=0; NEWT=0; COR=0; STILL=0
chan=$(grep -ohE '"channel":"[a-z_0-9]+"' "${F[DISK]}" "${F[MEM]}" | head -1 | cut -d'"' -f4)
declare -A S2; while IFS=$'\t' read -r id st; do S2[$id]=$st; done < <(jq -r '.techniques[] | [.techniqueID, (.comment | split(" ")[0])] | @tsv' "${F[4x02]}")
declare -A NM; while IFS=$'\t' read -r id nm; do NM[$id]=$nm; done < <(jq -r '.techniques[] | [.techniqueID, .tactic] | @tsv' "$NAV")
ids=$( (jq -r '.techniques[].techniqueID' "${F[4x02]}"; grep -ohE 'T1[0-9]{3}(\.[0-9]{3})?' "${F[MEM]}" "${F[DISK]}") | sort -u)
SHOWN=0; PART=0
for id in $ids; do
    c2=${S2[$id]:-ABSENT}; c3=$(tcite 4x03 "$id"); c4=$(tcite 4x04 "$id"); cm=$(tcite MEM "$id"); cd=$(tcite DISK "$id")
    ir=-; [ "$cm$cd" != "--" ] && ir=Y
    first=; [ "$c4" = Y ] && first=4x04; [ -z "$first" ] && [ "$ir" = Y ] && first=IR
    up=
    case "$c2" in
      OBSERVED) ;;
      INFERRED) if [ "$id" = T1048.003 ] && [ -n "$chan" ] && [ "$chan" != dns ]; then up="CORRECTED: exfil used $chan (HTTPS, T1041); DNS only 2 test pings"; COR=$((COR + 1))
                elif [ -n "$first" ]; then up="UPGRADED to CONFIRMED ($first)"; UPG=$((UPG + 1))
                elif [ "$c3" = Y ]; then PART=$((PART + 1)); else STILL=$((STILL + 1)); fi ;;
      *)        if [ -n "$first" ]; then up="NEW ($first)"; NEWT=$((NEWT + 1)); elif [ "$c3" = Y ]; then PART=$((PART + 1)); else STILL=$((STILL + 1)); fi ;;
    esac
    [ -n "$up" ] && [ "$ir" = Y -o "$id" = T1048.003 ] && TECHROWS+=("$(printf '  %-10s %-8.8s %-5s %-5s %-5s %s' "$id" "${c2/OBSERVED/OBS}" "$c3" "$c4" "$ir" "$up")")
done
OTHER=$(( UPG + NEWT - ${#TECHROWS[@]} + COR ))

bar
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: $(ls "${F[4x00]}" "${F[4x01]}" "${F[4x02]}" "${F[4x03]}" "${F[4x04]}" "${F[MEM]}" "${F[DISK]}" "${F[FW]}" "${F[NOTES]}" | wc -l) evidence files (4x00-4x04 summaries, IR memory/disk/firewall/notes)"
bar
echo
echo "IOC CORRELATION:   (CONVERGED = 2+ independent sources; 4x02 and IR notes do not count)"
printf '  %-30s %s\n' IOC "4x00 4x01 4x02 4x03 4x04 MEM  DISK FW   Status"
printf '%s\n' "${IOCROWS[@]}" | grep -v '^CONVERGED' | cut -d'|' -f2
echo "  CONVERGED ($ICONV): $(printf '%s\n' "${IOCROWS[@]}" | grep '^CONVERGED' | cut -d'|' -f3 | paste -sd, | sed 's/,/, /g')"
echo "  Summary: $ICONV CONVERGED, $ISINGLE SINGLE-SOURCE, $ICONF CONFLICTED, $IMO IOC-master-only (no trace in any evidence file) | New IOCs from IR: $NEWN${DUPS:+ (duplicate IDs for the same indicator: ${DUPS% })}"
echo
echo "TIMELINE CORRELATION: (UTC; Δ = spread between sources)"
printf '  %-36s %-14s %-15s %s\n' Event Sources Confidence Notes
printf '%s\n' "${EVROWS[@]}" | sort -t'|' -k1,1n | cut -d'|' -f2- | sed 's/^/  /'
echo
echo "  CONTRADICTIONS AND RESOLUTION:"
for c in "${CONFL[@]}"; do echo "  -> ${c%%|*}"; echo "     Resolution: ${c#*|}" | fold -s -w 96 | sed '2,$s/^/       /'; done
dl=$(norm "$(g 4x03 'First observed.*\(delivery\)')" 4x03); born=$(norm "$(awk '/svchost_update.exe/{f=1} f&&/ B: /{print;exit}' "${F[DISK]}")" DISK)
boot=$(norm "$(g MEM 'Boot time')" MEM); runk=$(norm "$(blk MEM '^\[K1\]' '^\[K2\]' | grep -m1 'Last Write')" MEM)
h1=$(grep -oE 'c8e2a9b4d1f7c0a3e6b9d2c5f8a1e4b7' "${F[4x03]}" | head -1); h2=$(grep -oE "$h1" "${F[DISK]}" | head -1)
[ -n "$dl" ] && [ -n "$born" ] && echo "  -> S2 delivered $(hhmm "$dl") (4x01/4x03) but file born on disk $(hhmm "$born") (+$(dur $((born - dl)))); hash ${h1:+identical in 4x03 and disk}
     Resolution: same binary re-created ${born:+$((born - boot))} s after the host boot ($(hhmm "$boot")) with its Run-key written +$((runk - boot)) s: the RAT re-installed itself at the reboot. Disk history only starts at that reboot (USN), so the 04-15 copy left no trace; infection date = 04-15."
gs=$(norm "$(grep -m1 'GAP STARTS' "${F[DISK]}")" DISK); ge=$(norm "$(grep -m1 'GAP ENDS' "${F[DISK]}")" DISK)
ins=$(jq -r '[.sessions[]? | select(.classification=="LATERAL_MOVEMENT" and (.ts_start|startswith("'"$(date -u -d @$gs +%F)"'")))] | first | "\(.ts_start) \(.ts_end) \(.dst_ip)"' "${F[FW]}")
if [ -n "$gs" ] && [ "$ins" != "null null null" ]; then s0=$(date -u -d "${ins%% *}" +%s); s1=$(date -u -d "$(cut -d' ' -f2 <<< "$ins")" +%s)
  echo "  -> Disk analyst says the 12-min log gap 'aligns with the second exfil session'; the second burst is $(fwq '[.sessions[]?|select(.classification=="EXFIL_BURST")][1].ts_start[0:10]'), the gap $(hhmm "$gs")
     Resolution: the gap lies inside the SMB session to $(cut -d' ' -f3 <<< "$ins") ($(hhmm "$s0")-$(hhmm "$s1")) = PsExec session #2, so it belongs to lateral movement, not exfil #2; the task's 02:00 run that day precedes it."; fi
esc=$(norm "$(g 4x04 'IR escalation issued')" 4x04); iso=$(norm "$(grep -m1 'isolation at' "${F[MEM]}" | sed -E 's/.*isolation at ([0-9:]+ CDT).*/\1 on '"$dd"'/')" MEM "$dd")
[ -n "$esc" ] && [ -n "$iso" ] && ((esc > iso)) && echo "  -> 4x04 says the hunt triggered IR (escalation $(hhmm "$esc")) but the host was isolated $(hhmm "$iso") (FW + memory agree)
     Resolution: isolation preceded the escalation by $(dur $((esc - iso))); the hunt report was finalised after the fact, so it did not trigger containment. Adopt FW/memory times."
echo
echo "TECHNIQUE CORRELATION: (rows where IR evidence is a source; $OTHER more were confirmed by 4x04 alone)"
printf '  %-10s %-8s %-5s %-5s %-5s %s\n' Technique 4x02 4x03 4x04 IR Update
printf '%s\n' "${TECHROWS[@]}"
echo "  Techniques UPGRADED from INFERRED to CONFIRMED: $UPG | newly identified: $NEWT | CORRECTED: $COR | capability-only (4x03 sandbox, no host evidence): $PART | still unconfirmed: $STILL"
echo
bar
