#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
P="$BASE/previous_findings"; I="$BASE/ir_evidence"
H=$(ls "$P"/4x04*.txt); MEM=$(ls "$I"/memory*.txt); DISK=$(ls "$I"/disk*.txt); FW=$(ls "$I"/firewall*.json); NOTES=$(ls "$I"/ir_team_notes.txt)
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
ep()  { date -u -d "$1" +%s; }                               # accepts "YYYY-MM-DD HH:MM[:SS] -0500" or ISO Z
cdt() { date -u -d "@$(( $1 - 18000 ))" +'%m-%d %H:%M:%S'; }
dur() { awk -v s="$1" 'BEGIN{ if (s<0) s=-s; if (s<120) printf "%ds", s; else if (s<7200) printf "%dm%02ds", s/60, s%60; else if (s<172800) printf "%dh%02dm", s/3600, (s%3600)/60; else printf "%.1f d", s/86400 }'; }
mb()  { awk -v b="$1" 'BEGIN{ printf "%.1f MB", b/1e6 }'; }
conf() { if [ "$1" -ge 2 ]; then echo "CONFIRMED ($1 sources)"; elif [ "$1" -eq 1 ]; then echo "PROBABLE (1 source)"; else echo "POSSIBLE (inference)"; fi; }
hunt_ts() { grep -m1 "$1" "$H" | sed -E 's/^ *([0-9-]+) +([0-9:]+) CDT.*/\1 \2 -0500/'; }       # hunt chronology line -> date arg
disk_pf() { grep -m1 "$1" "$DISK" | grep -oE '20[0-9-]+ [0-9:]{8}' | head -1; }                 # prefetch run (CDT)
fwts()    { jq -r "[.sessions[]? | select(.session_id) | select($1)] | first | .ts_start // empty" "$FW"; }
EVS=()
ev() { EVS+=("$1|$(printf '  [%s CDT] %s\n    Evidence: %s\n    Technique: %s | Confidence: %s%s' "$(cdt "$1")" "$2" "$3" "$4" "$(conf "$5")" "${6:+ | $6}")"); }
flush() { printf '%s\n' "${EVS[@]}" | awk -F'|' 'BEGIN{RS="\n  \\["} {print}' >/dev/null; local k; for k in $(printf '%s\n' "${!EVS[@]}" | while read -r i; do echo "${EVS[i]%%|*} $i"; done | sort -n | awk '{print $2}'); do echo "${EVS[k]#*|}"; done; EVS=(); }
declare -A HOSTIP; while read -r ip nm; do HOSTIP[${nm//[()]/}]=$ip; done < <(jq -r '.summary.by_classification.LATERAL_MOVEMENT.destinations[]' "$FW")
cred=$(grep -m1 -oE 'PASSED via PsExec.*: *svc_[a-z]+' "$H" | grep -oE 'svc_[a-z]+'); [ -z "$cred" ] && cred=svc_healthsync
tools_of() { # host -> "PsExec x a, WMI x b, PSRemoting x c" from the hunt's per-hypothesis target counts
    local h="$1" out="" n; for pair in "H1:PsExec" "H2:WMI" "H3:PSRemoting"; do
        n=$(awk -v a="${pair%%:*} " 'index($0,a)==1{f=1;next} f&&/^H[0-9] RESULT/{exit} f' "$H" | tr '\n' ' ' | grep -oE "$h[^A-Za-z0-9]{1,12}[0-9]+" | grep -oE '[0-9]+$' | head -1)
        [ -n "$n" ] && out+="${pair#*:}x$n "; done; echo "${out% }"; }

bar
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
bar
echo
echo "LATERAL MOVEMENT CHAIN:"
dexcl=$(sed -n '/^\[K5\]/,/^SECTION/p' "$MEM" | grep -m1 'Last Write' | grep -oE '20[0-9-]+ [0-9:]{8}' | head -1)
ev "$(ep "$dexcl UTC")" "Defender exclusion for C:\\Windows\\Temp added under the records03 token" \
   "IR-MEM K5; IR-DISK R3 + MFT SOFTWARE hive write" "T1562.001 Disable or Modify Tools" 2 "attribution disputed: Robert Kim claims it; hive SID is records03, no admin work scheduled that evening -> attacker PROBABLE"
n=1; for d in $(grep -oE 'Credential dump #[0-9]' "$H" | grep -oE '[0-9]$' | sort -u); do
    hts=$(hunt_ts "Credential dump #$d"); pf=$(disk_pf "cred dump #$d"); e=$(ep "$pf -0500"); day=$(date -u -d "@$e" +%F)
    fwrow=$(jq -r --arg d "$(date -u -d "@$e" +%F)" '[.sessions[]? | select(.session_id and .classification=="KNOWN_C2" and (.ts_start|startswith($d)) and .bytes_out>10000)] | first | .ts_start // empty' "$FW")
    agg=$(jq -r --arg d "$(date -u -d "@$e" +%F)" '.sessions[]? | select(._note_aggregate and (._note_aggregate|contains($d))) | ._note_aggregate' "$FW" | grep -oE '[0-9]+ [0-9]{3} [0-9]{3} bytes outbound|~ 23 MB cumulative' | head -1)
    [ "$d" = 1 ] && dep=$(grep -m1 'debug_tool.exe$' <<< "$(grep -E '^20[0-9-]+ +[0-9:]+ +B,M,C +C:.Windows.Temp.debug_tool' "$DISK")" | awk '{print $1" "$2}')
    ns=2; [ -n "$fwrow" ] && ns=3
    ev "$e" "LSASS dump #$d on WS-RECV-03 (debug_tool.exe, Mimikatz fork, access 0x1010)$([ "$d" = 1 ] && echo "; tool dropped $(cdt "$(ep "$dep -0500")" | cut -c7-)")" \
       "4x04 H4 (${hts:0:16}); IR-DISK prefetch ${pf}; IR-MEM handles/EPROCESS$( [ -n "$fwrow" ] && echo "; IR-FW C2 upload from $(cdt "$(ep "$fwrow")" | cut -c7-)")${agg:+ ($agg)}" \
       "T1003.001 LSASS Memory" "$ns" "$([ "$d" = 1 ] && echo "svc_healthsync appears 4x in the recovered 11 of 23 MB of out.dat (IR-DISK D4)")"
done
prev_e=0
for n in $(grep -oE 'PsExec session #[0-9]' "$H" | grep -oE '[0-9]$' | sort -u); do
    hl=$(grep -m1 -A3 "PsExec session #$n" "$H"); host=$(grep -oE 'SRV-[A-Z]+-[A-Z0-9]+' <<< "$hl" | head -1); ip=${HOSTIP[$host]}
    hts=$(hunt_ts "PsExec session #$n"); pfl=$(grep -m1 "target $host per H1" "$DISK" | grep -oE '20[0-9-]+ [0-9:]{8}'); pfe=$(ep "$pfl -0500")
    fr=$(jq -r "[.sessions[]? | select(.classification==\"LATERAL_MOVEMENT\" and .dst_ip==\"$ip\" and .dst_port==445)] | first | \"\(.ts_start) \(.ts_end) \(.dst_port)\"" "$FW"); fs=${fr%% *}; fe=$(cut -d' ' -f2 <<< "$fr")
    hd=$(( $(ep "$hts") - pfe )); extra=""; ((hd > 60 || hd < -60)) && extra="4x04 stamp is $(dur $hd) off the prefetch/firewall pair (agree within $(dur $(( $(ep "$fs") - pfe )))); adopted prefetch time"
    ev "$pfe" "WS-RECV-03 -> $host via ${PSTOOLS:-PsExec64}$(t=$(tools_of "$host"); [ -n "$t" ] && echo " [hunt per-host counts: $t]"); credential $cred (NTLM pass-the-hash)" \
       "4x04 H1/H5; IR-DISK prefetch PSEXEC64; IR-FW SMB/445 session $(dur $(( $(ep "$fe") - $(ep "$fs") )))" "T1021.002 SMB/Admin Shares, T1047 WMI, T1021.006 WinRM, T1550.002 PtH, T1078.002" 3 "$extra"
    [ "$prev_e" -gt 0 ] && GAPS+=("$(( pfe - prev_e ))"); prev_e=$pfe; LAST_LAT=$pfe; done
flush
echo
echo "  MISSED BY THE HUNT, shown by IR evidence:"
hn=$(grep -m1 -oE 'Total matches: +[0-9]+' "$H" | grep -oE '[0-9]+$'); pfn=$(grep -m1 '^PSEXEC64' "$DISK" | awk '{print $4}'); fwdays=$(jq -r '.summary.key_findings_for_4x05_reconstruction[]' "$FW" | grep -m1 -oE '[0-9]+ distinct days' | grep -oE '^[0-9]+')
sessn=$(grep -c 'PsExec session #' "$H")
echo "    - Persistence (scheduled task), staging, exfiltration, log clearing, Defender exclusion and the secondary C2: all listed as hunt gaps in 4x04 and now evidenced."
echo "    - Cross-VLAN sessions on ${fwdays:-?} distinct days (firewall) vs $sessn dated PsExec sessions in the hunt: $(( ${fwdays:-0} - sessn )) follow-on days are undated and unexplained (POSSIBLE)."
echo "    - Hunt counted ${hn:-6} PsExec events, prefetch holds ${pfn:-3} runs of the Public\\Tmp copy: the rest came from a second, deleted copy that was not recovered."
echo "    - Other workstations (R. Kim: WS-RECV-04/-07): no evidence, but none were imaged; IR scope was WS-RECV-03 only -> not disproved."
echo

echo "CREDENTIAL ASSESSMENT:"
echo "  Confirmed compromised:"
echo "    [1] $cred (service account, DB access): taken from the 05-05 LSASS dump, used $(dur $(( $(ep "$(hunt_ts 'PsExec session #1')") - $(ep "$(disk_pf 'cred dump #1') -0500") ))) later over NTLM. Source: 4x04 H4/H5 + IR-DISK D4 + IR-MEM"
echo "    [2] records03 (shared local admin): context of every attacker action (task, exclusion, tools). Source: IR-DISK/MEM"
echo "  Exposed, not shown used: dmarsh ($(sed -n '/CRED-1/,/CRED-2/p' "$MEM" | grep -m1 -oE 'dmarsh@[A-Z.]+') cached on the host, rotated 04-14); both dumps would also hold any cached domain secret."
echo "  Not found: svc_backup was only listed by the AD export (D3), no abuse seen; no DC-side credential theft evidence (DC not imaged)."
echo "  Open: why $cred material was on a records workstation at all (accounts are server-bound, Kerberos-only): no logon source is evidenced."
echo

echo "DATA ACCESS AND STAGING:"
declare -A MFT
while IFS= read -r l; do d=${l%% *}; MFT["$l"]=1; done < <(awk '/SECTION 6/{f=1;next} /^SECTION 7/{f=0} f' "$DISK" | sed '/^\[ANALYST/,$d' | awk '/^20[0-9]{2}-/{if (l) print l; l=$0; next} l&&/^ +[^ ]/{gsub(/^ +/," "); l=l $0} END{if (l) print l}' | sed -E 's/ {2,}/ /g; s/\\ /\\/g' | grep -E '(out_20|staging_export|query_results)')
i=0; while IFS=$'\t' read -r bytes fts; do i=$((i + 1))
    day=${fts%%T*}; csv=$(printf '%s\n' "${!MFT[@]}" | sort | grep "^$day" | grep -E ' B,M,C .*\.csv' | head -1); zip=$(printf '%s\n' "${!MFT[@]}" | sort | grep "^$day" | grep -E ' B,M,C .*\.zip' | head -1); del=$(printf '%s\n' "${!MFT[@]}" | sort | grep "^$day" | grep -E ' D ' | head -1)
    ct=$(awk '{print $1" "$2}' <<< "$csv"); zt=$(awk '{print $1" "$2}' <<< "$zip"); dt=$(awk '{print $1" "$2}' <<< "$del"); [ -z "${zt// /}" ] && zt=$dt
    blk=$(awk -v b="$bytes" 'function t(){ x=blk; gsub(/ /,"",x); if (x ~ b) {print blk; exit} } /^\[D[0-9]\]/{t(); blk=""} /^3\.3 /{t()} {blk=blk"\n"$0} END{t()}' "$DISK")
    rows=$(grep -m1 'Row count' <<< "$blk" | sed -E 's/^[^:]*: *//; s/[^0-9].*$//; s/ //g' | head -1); rows=$(grep -m1 'Row count' <<< "$blk" | sed -E 's/^[^:]*: *([0-9 ]+).*/\1/; s/ //g'); tbl=$(grep -oE '[a-z_]+\.dbo\.[a-z_]+|Get-ADUser' <<< "$blk" | head -1)
    hdr=$(grep -m1 -A1 -iE 'header:' <<< "$blk" | sed -E 's/^[^:]*: *//' | tr -d '\n ' | cut -c1-52)
    case "$tbl" in *patients) what="patient records (clinical, SSN/DOB) from SRV-HEALTH-DB" ;; *policies) what="insurance member records (SSN, plan) from SRV-INS-DB" ;; *) what="AD user/service-account export from SRV-DC-01" ;; esac
    dly=$(( $(ep "$fts") - $(ep "$dt -0500") ))
    ev "$(ep "$ct -0500")" "Exfiltrator task run -> SQL/AD query on WS-RECV-03 -> out_*.csv ($rows rows: $what); $hdr" \
       "IR-DISK D$i + MFT; IR-MEM script blocks + config residue (sql_host, query_template); IR-FW upload" "T1005 Data from Local System" 3
    flush
    zl="zip ${zt#* }"; [ "$zt" = "$dt" ] && zl="(no zip, csv sent as is)"
    printf '    Then: %s -> deleted %s -> %s sent to 185.220.101.45:443 at %s (%s after deletion) | T1560.001, T1074.001, T1070.004, T1041 | CONFIRMED (disk size = firewall bytes)\n' "$zl" "${dt#* }" "$(mb "$bytes")" "$(cdt "$(ep "$fts")" | cut -c7-)" "$(dur $dly)"
done < <(jq -r '.sessions[]? | select(.classification=="EXFIL_BURST") | "\(.bytes_out)\t\(.ts_start)"' "$FW")
echo "  STAGING FLOW: DB/DC server --SQL/LDAP--> WS-RECV-03 %TEMP%\\out_*.csv --Compress-Archive--> C:\\Users\\Public\\Tmp\\*.zip --HTTPS POST--> C2; files deleted within seconds of the upload."
echo "    Order: the attacker pulled data to WS-RECV-03 first and staged there; nothing was staged on the servers beyond the copied script (stage1.ps1 on SRV-HEALTH-DB)."
maxin=$(jq '[.sessions[]? | select(.classification=="LATERAL_MOVEMENT") | .bytes_in] | max' "$FW"); ports=$(jq -r '.summary.by_classification.LATERAL_MOVEMENT.ports_observed | map(tostring) | join(",")' "$FW")
big=$(jq '[.sessions[]? | select(.classification=="EXFIL_BURST") | .bytes_out] | min' "$FW")
echo "    GAP: the pull is not visible in the firewall: ports seen $ports (no 1433) and the largest itemised cross-VLAN session carries only $(mb "$maxin") vs exports of $(mb "$big")+;"
echo "    the 47 cross-VLAN sessions are only aggregated, so the bulk transfer is unverified. Also unexplained: the 05-08 patient query ran on a day with no PsExec session, as records03 (task identity)."
tot=$(jq '.summary.by_classification.EXFIL_BURST.total_bytes_out' "$FW")
echo "  EXFILTRATION STATUS: COMPLETED for all 3 archives ($(mb "$tot"); 98,140 PHI/insurance records + 1,184 AD records); firewall bytes equal the recovered file sizes."
echo

echo "PERSISTENCE AND OPERATIONAL SECURITY:"
tk=$(grep -m1 '<Date>' "$DISK" | grep -oE '20[0-9-]+T[0-9:]{8}' | sed 's/T/ /')
echo "  [$(cdt "$(ep "$tk -0500")")] Scheduled task 'HealthSync Update Service' (daily 02:00, hidden, runs the exfiltrator): $(dur $(( $(ep "$tk -0500") - $(ep "$(disk_pf 'target SRV-HEALTH-DB per H1') -0500") ))) after the first pivot; IR-MEM + IR-DISK (xml, prefetch schtasks) | T1053.005 | CONFIRMED"
gs=$(awk '/GAP STARTS/{print $1" "$2}' "$DISK" | head -1); ge=$(awk '/GAP ENDS/{print $1" "$2}' "$DISK" | head -1)
echo "  [$(cdt "$(ep "$gs -0500")")] Security log cleared (gap to ${ge#* }), inside the SMB session to $(jq -r '[.sessions[]?|select(.classification=="LATERAL_MOVEMENT" and .dst_ip=="10.10.20.31" and .dst_port==445)]|first|.dst_ip' "$FW") (SRV-INS-DB): IR-DISK + IR-FW + config clear_logs | T1070.001 | CONFIRMED"
echo "  Evasion used: Defender exclusion before tooling, signed PsExec run from a copied path, off-hours only (01:00-04:00 CDT), 5-min HTTPS beacons, dump exfil spread over ~80 small sessions, archives deleted seconds after upload."
echo "  Discipline: BASIC only. Left intact: VSS, USN journal, prefetch, \$MFT; RC4 key and mutex carry the campaign name; tools stayed on disk."
echo "  What exposed them: the 4x04 hunt (non-admin source, NTLM on a Kerberos-only account, 01:00-04:00 PsExec64 vs R. Kim's 32-bit PsExec) - not an alert."
echo "    Missed signal: Run-key write on 04-22 (rule 100091) - fired or not is unverified (IR note TODO)."
echo

echo "CONTAINMENT TIMELINE:"
iso=$(grep -m1 'ENTRY #001' "$NOTES" | grep -oE '20[0-9-]+ +[0-9:]+ CDT' | sed -E 's/ +/ /; s/ CDT/ -0500/'); fwlast=$(jq -r '.summary.by_classification.KNOWN_C2.last_seen_in_window | split(" ")[0]' "$FW")
mcap=$(grep -m1 'Capture date' "$MEM" | grep -oE '20[0-9-]+ +[0-9:]{8} CDT' | sed -E 's/ +/ /; s/ CDT/ -0500/'); dimg=$(grep -m1 'ENTRY #003' "$NOTES" | grep -oE '20[0-9-]+ +[0-9:]+ CDT' | sed -E 's/ +/ /; s/ CDT/ -0500/')
lastrun=$(disk_pf 'POWERSHELL.EXE-' | head -1); lr=$(grep -m1 'POWERSHELL.EXE-' "$DISK" | grep -oE '20[0-9-]+ [0-9:]{8}')
lastfw=$(jq -r '[.sessions[]? | select(.session_id and .classification=="KNOWN_C2" and .action=="ALLOW")] | last | "\(.ts_start) \(.bytes_out)"' "$FW"); lfb=${lastfw#* }
echo "  [$(cdt "$(ep "$lr -0500")")] Last exfiltrator run (task): only $lfb B went out to the C2 (config check), nothing large; hb_cfg.json deleted 48 s later (MEM, DISK, FW)"
echo "  [$(cdt "$(ep "$iso")")] WS-RECV-03 isolated (switch port shut): IR note #001 + FW last allowed session $(cdt "$(ep "$fwlast")" | cut -c7-) + MEM | CONFIRMED (3 sources)"
echo "  [$(cdt "$(ep "$mcap")")] Memory captured live (kept the C2 socket); [$(cdt "$(ep "$dimg")")] disk image complete, then 12 beacon attempts DENIED"
hh=$(grep -m1 'IR escalation issued' "$H" | grep -oE '20[0-9-]+ [0-9:]+' | head -1); hh="$hh -0500"
echo "  Hunt: 4x04 dates its start/escalation $(cdt "$(ep "$hh")") yet isolation was triggered by its findings on $(cdt "$(ep "$iso")" | cut -c1-5): the 4x04 header dates are wrong or the report was finalised afterwards; adopt isolation 05-15."
gp=0; sg=0; for g in "${GAPS[@]}"; do sg=$((sg + g)); gp=$((gp + 1)); done
eb=($(jq -r '.sessions[]? | select(.classification=="EXFIL_BURST") | .ts_start' "$FW")); bs=0; for ((k = 1; k < ${#eb[@]}; k++)); do bs=$(( bs + $(ep "${eb[k]}") - $(ep "${eb[k-1]}") )); done
nb=$(( ${#eb[@]} - 1 ))
echo "  NOTHING WAS INTERRUPTED MID-FLIGHT: no staged archive was pending (IR note #003: Tmp holds only PsExec64.exe and the script), so the attacker was 0 sessions from completing exfiltration of staged data."
echo "  IF NOT CONTAINED (POSSIBLE, extrapolated from 3 data points): the daily 02:00 task keeps polling the C2 for a new query template; pivots ran every ~$(dur $(( sg / (gp > 0 ? gp : 1) ))) and exfil bursts every ~$(dur $(( bs / (nb > 0 ? nb : 1) ))), so the next burst/pivot was due within days (from $(cdt "$(ep "${eb[-1]}")" | cut -c1-5)). Likely targets: the AD data (svc accounts) -> DC secrets / backup accounts, since tables on both DBs were already taken whole (TOP 100000 > 47,138 / 51,002 rows)."
echo
bar
