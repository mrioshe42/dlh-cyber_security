#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
[ -d "$BASE" ] || { echo "Evidence package not found: $BASE" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

DIRS=(previous_findings ir_evidence reference)
ISO='20[0-9]{2}-[0-9]{2}-[0-9]{2}'
EVIDENCE_TYPES="EMAIL NETWORK MALWARE SIEM MEMORY DISK FIREWALL"

bar()  { printf '%*s\n' 64 '' | tr ' ' '='; }
wrap() { fold -s -w "${2:-62}" <<< "$1" | sed "1!s/^/$3/"; }
isos() { grep -oE "$ISO"; }
d2e()  { date -u -d "$1" +%s; }

classify() {
    case "$1" in
        reference/*)       echo REFERENCE ;;
        *phishing*)        echo EMAIL ;;
        *firewall*)        echo FIREWALL ;;
        *network*)         echo NETWORK ;;
        *attack_mapping*)  echo INTEL ;;
        *malware*)         echo MALWARE ;;
        *hunt*)            echo SIEM ;;
        *memory*)          echo MEMORY ;;
        *disk*)            echo DISK ;;
        *ir_team*|*notes*) echo IR ;;
        *)                 echo OTHER ;;
    esac
}
phase_of() {
    local b; b=$(basename "$1")
    if [[ "$b" =~ ^(4x0[0-9]) ]]; then echo "${BASH_REMATCH[1]}"
    elif [[ "$1" == ir_evidence/* ]]; then echo "4x05-IR"
    else echo "Reference"; fi
}
is_json() { [[ "$1" == *.json ]]; }

title_of() {
    local f="$BASE/$1"
    if is_json "$1"; then
        jq -r '.name // .metadata.source // empty' "$f" 2>/dev/null
    else
        grep -vE '^[= -]*$' "$f" | head -2 | sed 's/^ *//' | paste -sd' ' | sed 's/  */ /g'
    fi
}

IOC="$BASE/reference/healthbane_ioc_master.json"
NAV="$BASE/reference/attck_navigator_80pct.json"
FW=$(find "$BASE/ir_evidence" -name '*firewall*.json' | head -1)
CAMPAIGN_FIRST=$(jq -r '.campaign.first_observed // empty' "$IOC" 2>/dev/null)
CAMPAIGN_LAST=$(jq -r '.campaign.last_internal_evidence // empty' "$IOC" 2>/dev/null | isos | head -1)

coverage_of() {
    local rel="$1" type="$2" f="$BASE/$1" s e line lab
    if [ "$type" = FIREWALL ] && is_json "$rel"; then
        jq -r '.metadata.time_range_utc | "\(.start[0:10]) \(.end[0:10])"' "$f"; return
    fi
    if [ "$type" = INTEL ] && is_json "$rel"; then       # intel runs from first contact to approval
        e=$(jq -r '.metadata[]? | select(.name=="approved") | .value' "$f" | isos | tail -1)
        echo "${CAMPAIGN_FIRST:-$e} $e"; return
    fi
    if [ "$type" = REFERENCE ]; then echo "- -"; return; fi
    for lab in "PCAP collection window" "USN journal range" "Hunt window" "Period covered" \
               "Capture date" "Investigation period"; do
        line=$(grep -m1 -E "^ *$lab" "$f") || continue
        read -r s e <<< "$(isos <<< "$line" | paste -sd' ')"
        [ -n "$s" ] && { echo "$s ${e:-$s}"; return; }
    done
    echo "- -"
}

reliability_of() {
    local rel="$1" f="$BASE/$1" low disp
    if grep -q '\[LOW\]' "$f" 2>/dev/null && grep -qi 'working' "$f"; then
        low=$(grep -c '\[LOW' "$f"); disp=$(grep -c 'DISPUTED' "$f")
        echo "LOW (preliminary working notes: $low [LOW], $disp DISPUTED tags)"; return
    fi
    case "$rel" in
        ir_evidence/*)
            local extra=""
            grep -qiE 'abridged' "$f" && extra=", abridged export"
            grep -q '\[ANALYST' "$f" && extra="$extra, contains [ANALYST] interpretation"
            if grep -qiE 'chain of custody|export_method' "$f"; then
                echo "HIGH (primary evidence, controlled collection$extra)"
            else echo "MEDIUM (IR file without custody record$extra)"; fi ;;
        previous_findings/*) echo "MEDIUM (derived findings from a previous investigation)" ;;
        reference/*)
            if grep -qiE 'assembled_from|Combines indicators|consolidated' "$f"; then
                echo "MEDIUM (consolidated from prior phases)"
            else echo "HIGH as authoritative context (not attack evidence)"; fi ;;
    esac
}

key_of() {
    local rel="$1" type="$2" f="$BASE/$1" ips n pur
    if is_json "$rel"; then
        case "$type" in
            FIREWALL)
                n=$(jq -r '.metadata.session_count_in_export' "$f")
                jq -r '"\(.summary.total_sessions_in_window) sessions in window, \(.metadata.session_count_in_export) in export"' "$f"
                jq -r '.summary.by_classification | to_entries[] |
                    "\(.key): \(.value.session_count) sess -> \((.value.destinations // []) | join(","))  \(.value.total_bytes_out // .value.total_bytes_out_including_exfil_bursts // 0) B out"' "$f" ;;
            INTEL) jq -r '.metadata[] | select(.name=="coverage_summary") | "ATT&CK " + .value' "$f" ;;
            *)     jq -r 'if .summary.total_iocs then "\(.summary.total_iocs) IOCs"
                          else empty end' "$f"
                   jq -r '.metadata[]? | select(.name=="coverage_summary") | "ATT&CK " + .value' "$f" ;;
        esac
        return
    fi
    pur=$(awk '/^PURPOSE/{p=1;next} p&&/^-+$/{next} p&&NF{print;c++} c==2{exit}' "$f" | sed 's/^ *//' | paste -sd' ')
        grep -E 'Emails confirmed malicious|Total emails analyzed|Samples analyzed|RESULT:|Credential PASSED|^ *\[NEW-[0-9]\]|Image acquired|^ *Heartbeat|Boot time' "$f" \
        | sed 's/^ *//; s/  */ /g' | head -3
    ips=$(grep -vE 'Imaging tool|Capture tool|version' "$f" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -vE '^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.)' | sort -u | head -6 | paste -sd' ')
    n=$(grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' "$f" | sort -u | wc -l)
    grep -q '\[DISPUTED' "$f" && echo "Tags: HIGH $(grep -c '^\[HIGH' "$f"), MED $(grep -c '^\[MED' "$f"), LOW $(grep -c '^\[LOW' "$f"), DISPUTED $(grep -c '^\[DISPUTED' "$f"), TODO $(grep -c '\[TODO' "$f")"
    [ -n "$ips" ] && echo "IPs: $ips"
    [ "$n" -gt 0 ] && echo "$n ATT&CK IDs cited"

}

declare -a COV_ROWS FILES TYPES_OF
N=0
print_catalog() {
    echo "SOURCE CATALOG:"
    local d rel type phase s e cov line first
    for d in "${DIRS[@]}"; do
        while IFS= read -r p; do
            rel="${p#$BASE/}"; type=$(classify "$rel"); phase=$(phase_of "$rel")
            N=$((N + 1)); FILES+=("$rel"); TYPES_OF+=("$type")
            read -r s e <<< "$(coverage_of "$rel" "$type")"
            if [ "$s" = "-" ]; then cov="static reference (not time-bounded)"
            elif [ "$s" = "$e" ]; then cov="$s (single point in time)"
            else cov="$s to $e"; COV_ROWS+=("$type|$s|$e|$rel"); fi
            [ "$s" = "$e" ] && [ "$s" != "-" ] && COV_ROWS+=("$type|$s|$e|$rel")
            printf '  [%02d] %s\n' "$N" "$(basename "$rel")"
            printf '       %s | %s | %s\n' "$phase" "$type" "$cov"
            printf '       Reliability: %s\n' "$(reliability_of "$rel" | sed 's/ (.*//')"
            printf '       Key: %s\n' "$(key_of "$rel" "$type" | grep -v 'ATT&CK IDs cited' | head -3 | paste -sd';' | sed 's/;/; /g; s/  */ /g' | cut -c1-110)"
        done < <(find "$BASE/$d" -maxdepth 1 -type f | sort)
    done
}

setup_days() {
    ANCHOR=$(printf '%s\n' "${COV_ROWS[@]}" | cut -d'|' -f2 | sort | head -1)
    END_DAY=$(printf '%s\n' "${COV_ROWS[@]}" | cut -d'|' -f3 | sort | tail -1)
    DAYS=$(( ($(d2e "$END_DAY") - $(d2e "$ANCHOR")) / 86400 + 1 ))
    BASEWEEK=$(grep -ohE 'Week [0-9]+' "$BASE"/previous_findings/4x00* 2>/dev/null | head -1 | grep -oE '[0-9]+')
    BASEWEEK=${BASEWEEK:-1}
    COV_TYPES=$(printf '%s\n' "${COV_ROWS[@]}" | cut -d'|' -f1 | awk '!s[$0]++' | paste -sd' ')
}
day_n() { echo $(( ($(d2e "$1") - $(d2e "$ANCHOR")) / 86400 )); }
day_s() { date -u -d "$ANCHOR + $1 days" +%Y-%m-%d; }
cov_has() {
    local row t s e
    for row in "${COV_ROWS[@]}"; do
        IFS='|' read -r t s e _ <<< "$row"
        [ "$t" = "$1" ] || continue
        [ "$2" -ge "$(day_n "$s")" ] && [ "$2" -le "$(day_n "$e")" ] && return 0
    done
    return 1
}

print_matrix() {
    echo "TEMPORAL COVERAGE MATRIX (Week $BASEWEEK = $ANCHOR):"
    echo
    printf '  %-8s %-13s' "Week" "Dates"
    local t w ws we i any cell n line1="" line2=""
    for t in $COV_TYPES; do printf ' %-10s' "$t"; done; echo
    for ((w = 0; w * 7 < DAYS; w++)); do
        ws=$((w * 7)); we=$((ws + 6)); [ $we -ge $DAYS ] && we=$((DAYS - 1))
        printf '  Week %-3s %-13s' "$((BASEWEEK + w))" "$(day_s $ws | cut -c6-)..$(day_s $we | cut -c6-)"
        for t in $COV_TYPES; do
            any=0
            for ((i = ws; i <= we; i++)); do cov_has "$t" "$i" && { any=1; break; }; done
            [ $any -eq 1 ] && cell=$(printf '%-8.8s' "$t" | tr ' ' '-') || cell="--------"
            printf ' [%s]' "$cell"
        done; echo
    done
}

GAP_LIST=()
runs() {
    local label="$1"; shift
    local i t any start=-1 found=0
    for ((i = 0; i <= DAYS; i++)); do
        any=0
        if [ $i -lt $DAYS ]; then for t in "$@"; do cov_has "$t" "$i" && { any=1; break; }; done
        else any=1; fi
        [ $any -eq 0 ] && [ $start -lt 0 ] && start=$i
        if [ $any -eq 1 ] && [ $start -ge 0 ]; then
            printf '  GAP: %s -- none %s to %s (%d days)\n' "$label" "$(day_s $start)" "$(day_s $((i - 1)))" $((i - start))
            GAP_LIST+=("$label|$(day_s $start)|$(day_s $((i - 1)))|$((i - start))")
            start=-1; found=1
        fi
    done
    [ $found -eq 0 ] && printf '  (ok) %s -- every day covered\n' "$label"
}

print_gaps() {
    echo "TEMPORAL GAPS:"
    runs "any evidence" $COV_TYPES
    runs "network telemetry (NETWORK, FIREWALL)" NETWORK FIREWALL
    runs "endpoint telemetry (SIEM, DISK, MEMORY)" SIEM DISK MEMORY
    for row in "${COV_ROWS[@]}"; do
        IFS='|' read -r t s e _ <<< "$row"
        [ "$t" = MEMORY ] && echo "  NOTE: $t is a single snapshot ($s)"
    done
}

declare -A TECH_TACTIC TECH_STATE TECH_SRC
print_domain_gaps() {
    echo "DOMAIN GAPS:"
    local id tactic cmt i f t re
    NOID=""
    for i in "${!FILES[@]}"; do
        t=${TYPES_OF[$i]}; [[ " $EVIDENCE_TYPES " == *" $t "* ]] || continue
        grep -qE 'T1[0-9]{3}' "$BASE/${FILES[$i]}" || NOID+="$t "
    done
    NOID=${NOID:-none}
    while IFS=$'\t' read -r id tactic cmt; do
        TECH_TACTIC[$id]=$tactic; TECH_STATE[$id]=${cmt%% *}
        re="${id//./\\.}([^0-9]|\$)"
        for i in "${!FILES[@]}"; do
            t=${TYPES_OF[$i]}; [[ " $EVIDENCE_TYPES " == *" $t "* ]] || continue
            grep -qE "$re" "$BASE/${FILES[$i]}" && [[ " ${TECH_SRC[$id]} " != *" $t "* ]] && TECH_SRC[$id]+="$t "
        done
    done < <(jq -r '.techniques[] | [.techniqueID, .tactic, .comment] | @tsv' "$NAV")

    GAP_TACTICS=(); UNMAPPED=(); SINGLE=()
    local tac cnt srcs ntech rows=""
    for tac in $(for id in "${!TECH_TACTIC[@]}"; do echo "${TECH_TACTIC[$id]}"; done | sort -u); do
        srcs=""; ntech=0
        for id in "${!TECH_TACTIC[@]}"; do
            [ "${TECH_TACTIC[$id]}" = "$tac" ] || continue
            ntech=$((ntech + 1))
            for t in ${TECH_SRC[$id]}; do [[ " $srcs " == *" $t "* ]] || srcs+="$t "; done
        done
        cnt=$(wc -w <<< "$srcs")
        rows+=$(printf '    %-24s %5d  %-3d %s' "$tac" "$ntech" "$cnt" "${srcs// /+}")$'\n'
        if [ "$cnt" -le 1 ]; then
            for id in "${!TECH_TACTIC[@]}"; do
                [ "${TECH_TACTIC[$id]}" = "$tac" ] && [ "${TECH_STATE[$id]}" != OBSERVED ] && { GAP_TACTICS+=("$tac"); break; }
            done
        fi
    done
    for id in $(printf '%s\n' "${!TECH_TACTIC[@]}" | sort); do
        cnt=$(wc -w <<< "${TECH_SRC[$id]}")
        [ "$cnt" -eq 0 ] && UNMAPPED+=("$id")
        [ "$cnt" -eq 1 ] && SINGLE+=("$id(${TECH_SRC[$id]% })")
    done
    [ ${#GAP_TACTICS[@]} -gt 0 ] && echo "  GAP: tactics with <=1 source type and unconfirmed techniques: ${GAP_TACTICS[*]}"
    [ ${#UNMAPPED[@]} -gt 0 ] && echo "  GAP: techniques with no direct evidence: ${UNMAPPED[*]}"

    NEW_TECH=(); UPGRADE=()
    local ir_ids rid
    ir_ids=$(cat "$BASE"/ir_evidence/{memory,disk}*.txt 2>/dev/null | grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' | sort -u)
    for rid in $ir_ids; do
        if [ -z "${TECH_TACTIC[$rid]}" ]; then NEW_TECH+=("$rid")
        elif [ "${TECH_STATE[$rid]}" != "OBSERVED" ]; then UPGRADE+=("$rid(${TECH_STATE[$rid]})"); fi
    done
    echo "  New in IR evidence (not in layer): ${NEW_TECH[*]:-none}"
    echo "  Upgraded by IR evidence: ${UPGRADE[*]%%(*}" | sed 's/([A-Z]*)//g'
    HOST_GAPS=()
    local h hs
    for h in $(jq -r '.iocs[] | select(.type=="host") | .value' "$IOC"); do
        hs=""
        for i in "${!FILES[@]}"; do
            t=${TYPES_OF[$i]}; f="$BASE/${FILES[$i]}"
            case "$t" in
                MEMORY|DISK) grep -qE "^ *Host: .*$h" "$f" && hs+="$t " ;;
                FIREWALL)    jq -e --arg h "$h" '.metadata.host_of_interest | contains($h)' "$f" >/dev/null 2>&1 && hs+="$t " ;;
                SIEM)        grep -qF "$h" "$f" && hs+="SIEM " ;;
            esac
        done
        [[ "$hs" == *MEMORY* || "$hs" == *DISK* ]] || HOST_GAPS+=("$h")
    done
    [ ${#HOST_GAPS[@]} -gt 0 ] && echo "  GAP: no memory/disk image for ${HOST_GAPS[*]} (SIEM only)"
}

FLAGS=()
flag() { FLAGS+=("$1"); }
print_flags() {
        local hunt iso appr hunt_end b1 b2 ja1 ja2 skew ab f
    f="$BASE/previous_findings"
    hunt=$(grep -m1 'IR escalation issued' "$f"/*hunt* | isos | head -1)
    iso=$(grep -m1 'Period covered' "$BASE"/ir_evidence/*notes* | isos | head -1)
    [ -n "$hunt" ] && [ -n "$iso" ] && [[ "$hunt" > "$iso" ]] && \
        flag "IR escalation is dated $hunt but the host was already isolated on $iso (IR notes); the hunt cannot be the trigger as stated"
    appr=$(jq -r '.metadata[]? | select(.name=="approved") | .value' "$NAV" | isos | head -1)
    hunt_end=$(printf '%s\n' "${COV_ROWS[@]}" | grep '^SIEM|' | cut -d'|' -f3 | sort | tail -1)
    jq -r '.name' "$NAV" | grep -qi 'post-4x04' && [ -n "$appr" ] && [[ "$appr" < "$hunt_end" ]] && \
        flag "Navigator layer is 'post-4x04' but approved $appr, before the hunt window ended ($hunt_end)"
    b1=$(grep -m1 -E 'GET /update/svchost_update' "$f"/*network* | isos | head -1)
    b2=$(awk '/svchost_update.exe/{f=1} f&&/ B: /{print;exit}' "$BASE"/ir_evidence/disk* | isos | head -1)
    [ -n "$b1" ] && [ -n "$b2" ] && [ "$b1" != "$b2" ] && \
        flag "svchost_update.exe downloaded $b1 (network) but born on disk $b2; re-drop after reboot or timestamp artifact?"
    [ -n "$CAMPAIGN_LAST" ] && [ -n "$FW" ] && \
        flag "IOC master last internal evidence is $CAMPAIGN_LAST but firewall data runs to $(jq -r '.metadata.time_range_utc.end[0:10]' "$FW"); activity after the last IOC is not in the IOC set"
    ja1=$(grep -m1 -oE 'JA3 hash: +[0-9a-f]{32}' "$f"/*network* | grep -oE '[0-9a-f]{32}')
    ja2=$(jq -r '.summary.by_classification.KNOWN_C2.ja3_observed // empty' "$FW")
    if [ -n "$ja1" ] && [ -n "$ja2" ]; then
        [ "$ja1" = "$ja2" ] && FLAGS+=("[ok] JA3 matches between 4x01 PCAP and firewall ($ja1): same C2 client") \
                            || flag "JA3 differs: 4x01 $ja1 vs firewall $ja2"
    fi
    skew=$(jq -r '.metadata._notes | join(" ")' "$FW" | grep -oE 'Firewall timestamps are [0-9]+ seconds [A-Z]+ of PCAP' | head -1)
    [ -n "$skew" ] && flag "(note) Clock skew declared: $skew"
    grep -lE 'CDT' "$BASE"/*/*.txt >/dev/null && grep -lE '[0-9]Z' "$BASE"/*/*.txt >/dev/null && \
        flag "(note) Sources mix CDT and UTC (Z) timestamps; normalise before merging"
    ab=$(jq -r '"\(.metadata.session_count_in_export) of \(.summary.total_sessions_in_window)"' "$FW")
    flag "(note) Firewall export is abridged ($ab sessions); the rest exist only as aggregates"
    flag "(note) IR notes: $(grep -c DISPUTED "$BASE"/ir_evidence/*notes*) DISPUTED and $(grep -c TODO "$BASE"/ir_evidence/*notes*) TODO lines, still unresolved"
}

print_questions() {
    echo "CRITICAL QUESTIONS FOR RECONSTRUCTION:"
    local q=0 g lab a b days ip c cls known
    ask() { q=$((q + 1)); printf '  [Q%d] %s\n' "$q" "$1"; }

    known=$(jq -r '.iocs[].value' "$IOC")
    for ip in $(jq -r '.summary.by_classification | to_entries[] | select(.key | test("BENIGN|BROWSING|INTERNAL") | not) | .value.destinations[]? | split(" ")[0] | split(":")[0]' "$FW" | sort -u); do
        grep -qF "$ip" <<< "$known" && continue
        [[ "$ip" =~ ^10\. ]] && continue
        c=$(jq -r --arg ip "$ip" '[.summary.by_classification | to_entries[] | select(.value.destinations // [] | map(startswith($ip)) | any) | "\(.key), \(.value.session_count) sessions, first seen \(.value.first_seen_in_window // "n/a")"] | first // empty' "$FW")
        ask "$ip is in non-benign firewall traffic but not in the IOC master${c:+ ($c)}. Secondary C2 or unrelated traffic?"
    done
    ask "Did the exfiltration succeed? Firewall: $(jq -r '[.summary.by_classification | to_entries[] | select(.key | test("EXFIL")) | "\(.value.session_count) sessions, \(.value.total_bytes_out) B"] | join("; ")' "$FW"); is it corroborated host-side?"
    ask "Does the firewall data confirm or contradict the 4x01 timeline (C2 start, interval, JA3)?"
    ask "What happened in the uncovered periods: $(for g in "${GAP_LIST[@]}"; do IFS='|' read -r lab a b days <<< "$g"; [ "${lab#any}" = "$lab" ] && echo -n "$a..$b (${lab%% *}); "; done)"
    [ ${#HOST_GAPS[@]} -gt 0 ] && ask "Were ${HOST_GAPS[*]} compromised beyond what SIEM shows (no memory/disk)?"
    ask "Are there persistence mechanisms beyond $(for id in "${!TECH_TACTIC[@]}"; do [ "${TECH_TACTIC[$id]}" = persistence ] && echo -n "$id "; done | sed 's/ $//; s/ /, /')?"
    ask "Which ATT&CK techniques remain unmapped? New: ${NEW_TECH[*]:-none}; still unconfirmed: ${#UPGRADE[@]}."
    local n=0 fl
    for fl in "${FLAGS[@]}"; do [[ "$fl" == "[ok]"* || "$fl" == "(note)"* ]] || n=$((n + 1)); done
    [ $n -gt 0 ] && ask "Resolve $n contradictions between sources (escalation vs isolation date, binary download vs disk birth, layer approval)."
}

bar
echo "   EVIDENCE INVENTORY - HEALTHBANE Reconstruction"
echo "   Analyst: $(hostname)    Date: $(date '+%Y-%m-%d %H:%M %Z')"
bar
echo
print_catalog
echo
setup_days
print_matrix
echo
print_gaps
echo
print_domain_gaps
echo
print_flags >/dev/null
print_questions
echo
bar
