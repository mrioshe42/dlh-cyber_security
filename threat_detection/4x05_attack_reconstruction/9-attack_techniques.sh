#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
P="$BASE/previous_findings"; I="$BASE/ir_evidence"
declare -A FILE=( [4x00]=$(ls "$P"/4x00*.txt) [4x01]=$(ls "$P"/4x01*.txt) [4x03]=$(ls "$P"/4x03*.txt) [4x04]=$(ls "$P"/4x04*.txt)
                  [MEM]=$(ls "$I"/memory*.txt) [DISK]=$(ls "$I"/disk*.txt) [FW]=$(ls "$I"/firewall*.json) )
NAV="$BASE/reference/attck_navigator_80pct.json"; L02=$(ls "$P"/4x02*.json); NOTES="$I/ir_team_notes.txt"
ORDER=(4x00 4x01 4x03 4x04 MEM DISK FW); OBS=" 4x00 4x01 4x04 MEM DISK FW "
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

SIG=(
 "T1566.001|Phishing: Spearphishing Attachment|April-Invoice|\.docm"
 "T1566.002|Phishing: Spearphishing Link|meddefense-portal\.com|credential-harvest"
 "T1583.001|Acquire Infrastructure: Domains|(registered|issued) 2026-04-12"
 "T1204.002|User Execution: Malicious File|enable.macros|macro click|after Diane opened"
 "T1059.001|Command and Scripting: PowerShell|EncodedCommand|powershell\.exe"
 "T1059.005|Command and Scripting: Visual Basic|VBA|dropper macro"
 "T1027|Obfuscated Files or Information|obfuscat|base64"
 "T1027.010|Obfuscation: Command Obfuscation|EncodedCommand"
 "T1140|Deobfuscate/Decode Files|decod"
 "T1105|Ingress Tool Transfer|/update/svchost_update"
 "T1547.001|Boot/Logon Autostart: Run Keys|Run.HealthSync|Run-key"
 "T1053.005|Scheduled Task/Job: Scheduled Task|HealthSync Update Service"
 "T1071.001|App Layer Protocol: Web Protocols|api/v1/checkin|185\.220\.101\.45"
 "T1071.004|App Layer Protocol: DNS|data-sync\.healthbane-c2\.net|TXT query"
 "T1573.001|Encrypted Channel: Symmetric Crypto|RC4"
 "T1571|Non-Standard Port|8443"
 "T1078|Valid Accounts|dmarsh|svc_healthsync"
 "T1078.002|Valid Accounts: Domain Accounts|Credential PASSED|NTLM.*svc_|appearing four times"
 "T1003.001|OS Credential Dumping: LSASS Memory|debug_tool|lsass"
 "T1550.002|Use Alt. Auth Material: Pass the Hash|pass-the-hash|PtH"
 "T1021.002|Remote Services: SMB/Admin Shares|PsExec"
 "T1021.006|Remote Services: Windows Remote Mgmt|Enter-PSSession|wsmprovhost"
 "T1047|Windows Management Instrumentation|WMIC|wmiprvse"
 "T1112|Modify Registry|PSEXESVC"
 "T1005|Data from Local System|out_2026|query_results|staging_export"
 "T1074.001|Data Staged: Local Data Staging|staging_export|Public.Tmp.out_"
 "T1560.001|Archive Collected Data: Archive via Utility|Compress-Archive|staging_export_00"
 "T1041|Exfiltration Over C2 Channel|EXFIL_BURST|c2_post"
 "T1048.003|Exfil Over Alt. Protocol: Unencrypted|DNS exfil|TXT query"
 "T1070.001|Indicator Removal: Clear Windows Event Logs|wevtutil cl (Security|Application)|clear_logs|GAP STARTS"
 "T1070.004|Indicator Removal: File Deletion|\(DELETED"
 "T1562.001|Impair Defenses: Disable/Modify Tools|Exclusions"
)
declare -A NAME SIGRE; for r in "${SIG[@]}"; do IFS='|' read -r id nm rest <<< "$r"; NAME[$id]=$nm; SIGRE[$id]=$(cut -d'|' -f3- <<< "$r"); done
hits() {
    grep -qE "${1//./\\.}([^0-9]|\$)" "${FILE[$2]}" 2>/dev/null && return 0
    [ -n "${SIGRE[$1]}" ] && grep -qE "${SIGRE[$1]}" "${FILE[$2]}" 2>/dev/null; }

declare -A BTAC BST BCOM
while IFS=$'\t' read -r id tac st cm; do BTAC[$id]=$tac; BST[$id]=$st; BCOM[$id]=$cm; done < <(jq -r '.techniques[] | [.techniqueID, .tactic, (.comment|split(" ")[0]), .comment] | join("\t")' "$NAV")
declare -A S02; while IFS=$'\t' read -r id st; do S02[$id]=$st; done < <(jq -r '.techniques[] | [.techniqueID, (.comment|split(" ")[0])] | join("\t")' "$L02")

EXTRA=$(cat "${FILE[MEM]}" "${FILE[DISK]}" "$NOTES" | grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' | sort -u | while read -r t; do [ -z "${BST[$t]}" ] && echo "$t"; done)
chan=$(grep -ohE '"channel":"[a-z_0-9]+"' "${FILE[DISK]}" "${FILE[MEM]}" | head -1 | cut -d'"' -f4)
tacs() { sed 's/initial-access/Init Access/; s/command-and-control/C2/; s/defense-evasion/Def Evasion/; s/credential-access/Cred Access/; s/lateral-movement/Lateral Mvmt/; s/resource-development/Resource Dev/; s/exfiltration/Exfiltration/; s/persistence/Persistence/; s/collection/Collection/; s/execution/Execution/' <<< "$1"; }
declare -A OF TAC

ALL=$( { jq -r '.techniques[].techniqueID' "$NAV"; echo "$EXTRA"; } | grep -v '^$')
TOTAL0=$(jq '.techniques | length' "$NAV"); TOTAL=$(wc -l <<< "$ALL")
ROWS=(); declare -A CNT; UPG=(); NEW=(); DOWN=(); COR=(); GAPS=()
declare -A FIRST CONF STAT SRCS
for id in $ALL; do
    obs=0; cap=0; first=; srcs=; ir=0
    for s in "${ORDER[@]}"; do hits "$id" "$s" || continue
        srcs+="$s,"; [ -z "$first" ] && first=$s
        [[ "$OBS" == *" $s "* ]] && obs=$((obs + 1)); [ "$s" = 4x03 ] && cap=1; [[ "$s" == MEM || "$s" == DISK || "$s" == FW ]] && ir=1; done
    if   [ "$obs" -ge 2 ] || { [ "$obs" -eq 1 ] && [ "$cap" -eq 1 ]; }; then c=CONF
    elif [ "$obs" -eq 1 ]; then c=PROB
    elif [ "$cap" -eq 1 ]; then c=POSS; else c=NONE; fi
    base=${BST[$id]:-ABSENT}; stat=
    case "$base" in
        OBSERVED) if [ "$c" = CONF ]; then stat=UNCHANGED; else stat=DOWNGRADED; fi ;;
        INFERRED) if [ "$c" = CONF ]; then stat=UPGRADED; elif [ "$c" = NONE ]; then stat="STILL INFERRED"; else stat=UPGRADED; fi ;;
        *)        if [ "$c" != NONE ]; then stat=NEW; else stat=GAP; fi ;;
    esac
    note=
    if [ "$id" = T1048.003 ] && [ -n "$chan" ] && [ "$chan" != dns ]; then stat=CORRECTED; c=POSS; note="channel=$chan (HTTPS to C2): DNS exfil never used, 2 test pings only"; fi
    if [ "$id" = T1566.001 ] && [[ "${BCOM[$id]}" == *click* ]]; then stat="UNCHANGED*"; note="layer cites the click (a link = T1566.002); the .docm attachment is the real evidence"; fi
    [ "$id" = T1583.001 ] && [ "$stat" = DOWNGRADED ] && note="attacker-side artifact: only the 4x00 WHOIS lookup supports it; not re-verifiable from the IR evidence"
    [ "$id" = T1041 ] && [ "$stat" = UPGRADED ] && note="layer said 'interrupted at staging': firewall+disk show all 3 archives uploaded"
    [ "$id" = T1112 ] && [ "$stat" = DOWNGRADED ] && note="PSEXESVC key is in the IOC master but in no evidence file: inferred from PsExec behaviour"
    [ "$id" = T1550.002 ] && [ "$stat" = DOWNGRADED ] && note="4x04: PtH 'cannot be proven'; NTLM logon + dump are consistent with it, no hash-use event"
    FIRST[$id]=$first; CONF[$id]=$c; STAT[$id]=$stat; SRCS[$id]=${srcs%,}
    ROWS+=("$id|${NAME[$id]:-?}|${BTAC[$id]:-$(case $id in T1070.004|T1562.001) echo defense-evasion;; T1571) echo command-and-control;; *) echo '?';; esac)}|$c|$first|${srcs%,}|$stat|$note")
done

fl() { case "$1" in 4x00|4x01|4x03|4x04) echo "$1" ;; MEM|DISK|FW) echo 4x05-IR ;; *) echo - ;; esac; }
sn() { sed 's/MEM/IR-MEM/; s/DISK/IR-DISK/; s/FW/IR-FW/' <<< "$1"; }
bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
bar
echo "   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)"
echo "   Threat model: $TOTAL0 techniques in the baseline layer + $(wc -w <<< "$EXTRA") new from IR evidence = $TOTAL"
bar
echo
printf '  %-3s %-10s %-40s %-12s %-5s %-8s %-22s %s\n' '#' Technique Name Tactic Conf 'First ID' Sources Status
n=0; for r in "${ROWS[@]}"; do IFS='|' read -r id nm tac c first srcs stat note <<< "$r"; n=$((n + 1)); CNT[$c]=$(( ${CNT[$c]:-0} + 1 ))
    printf '  %02d  %-10s %-40.40s %-12s %-5s %-8s %-22.22s %s\n' "$n" "$id" "$nm" "$(tacs "$tac")" "$c" "$(fl "$first")" "$(sn "$srcs")" "$stat"
    [ -n "$note" ] && printf '      -> %s\n' "$note"
    case "$stat" in UPGRADED) UPG+=("$id") ;; NEW) NEW+=("$id") ;; DOWNGRADED) DOWN+=("$id") ;; CORRECTED) COR+=("$id") ;; GAP|"STILL INFERRED") GAPS+=("$id") ;; esac
    [ "$c" = CONF ] || [ "$c" = PROB ] || GAPS+=("$id"); done
echo
echo "COVERAGE EVOLUTION (recomputed from the evidence files up to each investigation; 4x02 and IR notes not counted):"
stage() {
    local upto=$1 any=0 cf=0 id s o c ob cp a
    for id in $(jq -r '.techniques[].techniqueID' "$NAV"); do ob=0; cp=0; a=0
        for s in "${ORDER[@]}"; do hits "$id" "$s" && { a=1; [[ "$OBS" == *" $s "* ]] && ob=$((ob + 1)); [ "$s" = 4x03 ] && cp=1; }; [ "$s" = "$upto" ] && break; done
        any=$((any + a)); { [ "$ob" -ge 2 ] || { [ "$ob" -eq 1 ] && [ "$cp" -eq 1 ]; }; } && cf=$((cf + 1)); done
    echo "$any $cf"; }
c02o=$(jq '[.techniques[] | select(.comment|startswith("OBSERVED"))] | length' "$L02"); c02i=$(jq '[.techniques[] | select(.comment|startswith("INFERRED"))] | length' "$L02")
pct() { echo $(( $1 * 100 / $2 )); }
echo "  Post-4x02 (intel, as filed):  $c02o observed + $c02i inferred of $TOTAL0 = $(pct $c02o $TOTAL0)% observed, $(pct $((c02o + c02i)) $TOTAL0)% mapped"
for st in "4x01:Post-4x01 (network) " "4x03:Post-4x03 (malware) " "4x04:Post-4x04 (hunting) "; do u=${st%%:*}; read -r an cn <<< "$(stage "$u")"; echo "  ${st#*:}  any evidence $an/$TOTAL0 ($(pct "$an" "$TOTAL0")%), CONFIRMED by the rule $cn/$TOTAL0 ($(pct "$cn" "$TOTAL0")%)"; done
lo=$(jq '[.techniques[] | select(.comment|startswith("OBSERVED"))] | length' "$NAV"); li=$(jq '[.techniques[] | select(.comment|startswith("INFERRED"))] | length' "$NAV"); ln=$(( TOTAL0 - lo - li ))
claim=$(jq -r '.metadata[] | select(.name=="coverage_summary") | .value' "$NAV")
echo "  Baseline layer ($(basename "$NAV")): $lo observed / $li inferred / $ln not covered -> $(pct "$lo" "$TOTAL0")%; its own summary claims '$claim'$( [[ "$claim" != "$lo OBSERVED"* ]] && echo " -> MISMATCH, recount used")"
conf=${CNT[CONF]:-0}; prob=${CNT[PROB]:-0}; poss=${CNT[POSS]:-0}
c29=0; for r in "${ROWS[@]}"; do IFS='|' read -r id _ _ c _ <<< "$r"; [ -n "${BST[$id]}" ] && [ "$c" = CONF ] && c29=$((c29 + 1)); done
echo "  Post-4x05 (reconstruction):   CONFIRMED $c29/$TOTAL0 = $(pct "$c29" "$TOTAL0")% of the original model; $conf/$TOTAL = $(pct "$conf" "$TOTAL")% incl. the $(wc -w <<< "$EXTRA") new techniques; with PROBABLE: $((conf + prob))/$TOTAL = $(pct $((conf + prob)) "$TOTAL")%"
echo
echo "UPGRADED (INFERRED -> CONFIRMED): ${#UPG[@]}"
for id in "${UPG[@]}"; do echo "  $id ${NAME[$id]}: $(sn "${SRCS[$id]}")"; done
echo "NEW (not covered in the baseline layer, or outside it): ${#NEW[@]}"
for id in "${NEW[@]}"; do echo "  $id ${NAME[$id]}: $(sn "${SRCS[$id]}")$( [ -z "${BST[$id]}" ] && echo " [outside the 29-technique model]")"; done
echo "DOWNGRADED: ${#DOWN[@]} ($(printf '%s ' "${DOWN[@]}"))   CORRECTED: ${#COR[@]} ($(printf '%s ' "${COR[@]}"))"
echo
echo "REMAINING GAP: techniques without CONFIRMED evidence"
for r in "${ROWS[@]}"; do IFS='|' read -r id nm tac c first srcs stat note <<< "$r"; [ "$c" = CONF ] && continue
    case "$id" in
      T1048.003) as="not employed: every exfil burst went HTTPS to the C2; no external DNS sessions in the firewall export. Capability exists in the code." ;;
      T1112)     as="cannot determine: service-registration key not recovered (targets SRV-HEALTH-DB / SRV-INS-DB / SRV-DC-01 were not imaged) - collection limitation." ;;
      T1550.002) as="cannot prove pass-the-hash vs password reuse; needs DC-side logon detail (DC not imaged) - collection limitation." ;;
      *)         as="evidence is single-source or capability-only." ;; esac
    echo "  $id ${NAME[$id]}: $c  Assessment: $as"; done
echo
bar
