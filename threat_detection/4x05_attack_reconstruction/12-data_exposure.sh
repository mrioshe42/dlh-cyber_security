#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
INV="$BASE/reference/meddefense_asset_inventory.txt"; TOPO="$BASE/reference/network_topology.txt"
DISK=$(ls "$BASE"/ir_evidence/disk*.txt); FW=$(ls "$BASE"/ir_evidence/firewall*.json); NOTES="$BASE/ir_evidence/ir_team_notes.txt"
H=$(ls "$BASE"/previous_findings/4x04*.txt); MEM=$(ls "$BASE"/ir_evidence/memory*.txt)
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
mb()  { awk -v b="$1" 'BEGIN{ printf "%.1f MB", b/1e6 }'; }
num() { awk -v n="$1" 'BEGIN{ s=sprintf("%d", n); o=""; while (length(s) > 3) { o="," substr(s, length(s)-2) o; s=substr(s, 1, length(s)-3) } print s o }'; }
ep()  { date -u -d "$1" +%s; }
dur() { awk -v s="$1" 'BEGIN{ if (s<0) s=-s; if (s<172800) printf "%dh%02dm", s/3600, (s%3600)/60; else printf "%.1f days", s/86400 }'; }
inv() {
    awk -v h="--- $1 ---" -v f="$2" '$0==h{b=1;next} b&&/^--- /{exit} b&&index($0,f)>0{sub(/^[^:]*: */,""); print; exit}' "$INV"; }
invl() { awk -v h="--- $1 ---" '$0==h{b=1;next} b&&/^--- /{exit} b' "$INV"; }

DB=$(awk '/^3\.2 /{f=1} /^3\.3 /{f=0} f' "$DISK")
ART=(); for d in $(grep -oE '^\[D[0-9]+\]' <<< "$DB" | tr -d '[]'); do
    b=$(awk -v i="[$d]" 'index($0,i)==1{f=1;print;next} f&&/^\[D[0-9]+\]/{exit} f' <<< "$DB")
    rows=$(grep -m1 'Row count' <<< "$b" | sed -E 's/^[^:]*: *([0-9 ]+).*/\1/; s/ //g'); [ -z "$rows" ] && continue
    sz=$(grep -m1 'Recovered size' <<< "$b" | grep -oE '[0-9 ]+ bytes' | tr -dc 0-9)
    host=$(grep -oE 'SRV-[A-Z]+-[A-Z0-9]+' <<< "$b" | head -1); tbl=$(grep -oE '[a-z_]+\.dbo\.[a-z_]+' <<< "$b" | head -1)
    hdr=$(grep -m1 -A1 -iE 'header:' <<< "$b" | sed -E 's/^[^:]*: *//' | tr -d '\n ')
    nm=$(head -1 <<< "$b" | sed -E 's/^\[D[0-9]+\] +//; s/ +\(.*//; s/.*\\//')
    ART+=("$d|$nm|$sz|$rows|$host|$tbl|$hdr"); done
tot_staged=0; for a in "${ART[@]}"; do IFS='|' read -r d nm sz rows host tbl hdr <<< "$a"; tot_staged=$((tot_staged + sz)); done
isoline=$(grep -m1 'ENTRY #001' "$NOTES"); iso=$(grep -oE '20[0-9-]+ +[0-9:]+ CDT' <<< "$isoline" | sed -E 's/ +/ /; s/ CDT/ -0500/')

bar
echo "   DATA EXPOSURE ASSESSMENT"
bar
echo
echo "COMPROMISED SYSTEM MAPPING:"
printf '  %-14s %-34s %-30s %-17s %s\n' Host Role "Data sensitivity" Access Basis
row() { printf '  %-14s %-34.34s %-30.30s %-17s %s\n' "$@"; }
v3=$(awk '/^--- VLAN-3/{b=1;next} b&&/^--- /{exit} b&&/Data sensitivity:/{sub(/^[^:]*: */,""); print; exit}' "$INV")
row WS-RECV-03 "Records WS (staging host)" "${v3%%  (*} (transient PHI)" CONFIRMED "attacker tools, staged archives, task (disk/memory)"
for host in SRV-HEALTH-DB SRV-INS-DB SRV-DC-01; do
    role=$(inv "$host" "Role:"); sens=$(inv "$host" "Data sensitivity:" | sed -E 's/  *\(.*//'); phi=$(inv "$host" "PHI on this host:" | awk '{print $1}')
    art=$(printf '%s\n' "${ART[@]}" | awk -F'|' -v h="$host" '$5==h{print; exit}')
    if [ -n "$art" ]; then IFS='|' read -r d nm sz rows h2 tbl hdr <<< "$art"; acc=CONFIRMED; basis="$nm: $(num "$rows") rows${tbl:+ from $tbl}"
    else acc=POTENTIAL; basis="credential + network reach only"; fi
    row "$host" "$role" "$sens${phi:+, PHI=$phi}" "$acc" "$basis"
done
fl=$(inv SRV-FILE-01 "Data sensitivity:" | sed -E 's/  *\(.*//')
row SRV-FILE-01 "$(inv SRV-FILE-01 'Role:')" "$fl, PHI=imaging share" "NO EVIDENCE" "only benign records03 H: mounts in the firewall; see IP conflict"
echo "  Not in the attacker chain, no evidence: SRV-DC-02, SRV-BACKUP-01, SRV-PATCH-01, SRV-AV-01, other workstations (R. Kim's WS-RECV-04/-07 claim unverified: not imaged)."
echo "  DC-01 detail: AD user export read (confirmed); NTDS.dit / DCSync: no evidence either way (DC not imaged) -> POTENTIAL, inventory impact if true: $(inv SRV-DC-01 'Compromise impact:' | sed -E 's/\..*//')."
ipmap=""
for h in SRV-HEALTH-DB SRV-INS-DB SRV-FILE-01 SRV-DC-01; do
    iv=$(inv "$h" "IP:"); tp=$(grep -m1 -E "^ +$h " "$TOPO" | awk '{print $2}'); fp=$(jq -r --arg h "$h" '[.summary.by_classification[]? | .destinations[]? | select(contains($h))] | first // empty' "$FW" | awk '{print $1}')
    [ -z "$fp" ] && fp=$(jq -r --arg h "$h" '.metadata.iocs_relevant[]? | select(contains($h))' "$FW" | awk '{print $1}' | head -1)
    [ "$iv" = "$fp" ] && [ "$iv" = "$tp" ] || ipmap+="$h inv=$iv topo=${tp:--} fw=${fp:--}; "; done
echo "  EVIDENCE-QUALITY FLAG - host/IP mapping disagrees across sources: ${ipmap%; }"
echo "    -> HEALTH-DB/INS-DB identity rests on names (4x04 /node:, CSV schema), not IPs; confirm with DNS/ARP before the report is final."
echo

echo "EXFILTRATION STATUS:"
echo "  Data staged on WS-RECV-03: YES ($(mb "$tot_staged") in ${#ART[@]} recovered exports, $(for a in "${ART[@]}"; do IFS='|' read -r d nm sz rows h t hd <<< "$a"; [ -n "$rows" ] && echo -n "$nm "; done | sed 's/ $//; s/ /, /g'))"
read -r nb tb dst <<< "$(jq -r '.summary.by_classification.EXFIL_BURST as $e | [$e.session_count, $e.total_bytes_out] | @tsv' "$FW") $(jq -r '[.sessions[]? | select(.classification=="EXFIL_BURST")] | first | "\(.dst_ip):\(.dst_port)"' "$FW")"
match=0; for a in "${ART[@]}"; do IFS='|' read -r d nm sz rows h t hd <<< "$a"; [ -n "$rows" ] && jq -e --argjson b "$sz" '[.sessions[]? | select(.bytes_out==$b)] | length > 0' "$FW" >/dev/null && match=$((match + 1)); done
echo "  Transmitted externally: YES - $nb uploads, $(mb "$tb") to $dst (the primary C2 from 4x01); $match/${#ART[@]} recovered files match an upload byte for byte"
fb=$(jq -r '[.sessions[]? | select(.classification=="EXFIL_BURST")] | first | .ts_start' "$FW"); lb=$(jq -r '[.sessions[]? | select(.classification=="EXFIL_BURST")] | last | .ts_start' "$FW")
dump=$(jq -r '[.sessions[]? | select(._note_aggregate and (._note_aggregate|contains("LSASS"))) | ._note_aggregate | capture("(?<n>[0-9 ]{9,}) bytes outbound").n | gsub(" ";"") | tonumber] | add // 0' "$FW")
echo "  Also sent: LSASS dump output (credentials), about $(mb "$dump") on 05-05 alone plus a similar volume on 05-12 (firewall notes); secondary C2 carried only $(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.total_bytes_out' "$FW") B out."
echo "  Interruption: none. Last upload $(date -u -d "$lb" +'%m-%d %H:%M')Z, isolation $(date -u -d "@$(ep "$iso")" +'%m-%d %H:%M')Z ($(dur $(( $(ep "$iso") - $(ep "$lb") ))) later); first upload to isolation: $(dur $(( $(ep "$iso") - $(ep "$fb") )))."
echo "  CONCLUSION: staging confirmed AND exfiltration COMPLETED for every staged export; the 'interrupted before exfiltration' reading is not supported by the firewall data."
echo

echo "DATA EXPOSURE BY TYPE:"
a1=$(printf '%s\n' "${ART[@]}" | awk -F'|' '$5=="SRV-HEALTH-DB"'); a2=$(printf '%s\n' "${ART[@]}" | awk -F'|' '$5=="SRV-INS-DB"'); a3=$(printf '%s\n' "${ART[@]}" | awk -F'|' '$5=="SRV-DC-01"')
r1=$(cut -d'|' -f4 <<< "$a1"); r2=$(cut -d'|' -f4 <<< "$a2"); r3=$(cut -d'|' -f4 <<< "$a3"); h1=$(cut -d'|' -f7 <<< "$a1"); h2=$(cut -d'|' -f7 <<< "$a2")
inv1=$(inv SRV-HEALTH-DB "Records at risk:" | grep -oE '[0-9 ]{5,}' | head -1 | tr -d ' '); inv2=$(inv SRV-INS-DB "Records at risk:" | grep -oE '[0-9 ]{5,}' | head -1 | tr -d ' ')
cols=$(invl SRV-HEALTH-DB | sed -n '/Field-level PHI:/,/Records at risk/p' | grep -oE '[a-z_]+\.[a-z_*]+' | sort -u)
gone=""; kept=""; for c in $cols; do col=${c#*.}; [[ ",$h1," == *"$col"* || "$h1" == *"$col"* ]] && gone+="$c " || kept+="$c "; done
echo "  Patient health records (PHI) - EXFILTRATED: $(num "$r1") rows = the whole patients table (inventory ~$(num "$inv1"))"
echo "    Fields sent: ${h1:0:70}. Not evidenced as read (potential, DB credential reached all of health_records): ${kept}"
echo "    Evidence: IR-DISK ($(cut -d'|' -f2 <<< "$a1")), IR-FW upload, IR-MEM exfil script + config, 4x04 H1/H3 on SRV-HEALTH-DB"
echo "  Insurance/billing data - EXFILTRATED: $(num "$r2") rows of the policies/members export (inventory ~$(num "$inv2")); ${h2:0:62}"
echo "    Not evidenced: claims_line (ICD-10 codes), billing tables (potential via the same credential class)."
echo "  Employee records (HR forms, SRV-FILE-01 \\shared\\hr, ~$(invl SRV-FILE-01 | grep -m1 -oE '~ [0-9]+ records' | tr -dc 0-9) people) - NOT EXPOSED on current evidence: no attacker session to that server; IP conflict above keeps this open."
echo "  Operational/auth data - EXFILTRATED: AD user export ($(num "$r3") accounts incl. service accounts, group membership, last logon, SPNs) + LSASS credential material; NTDS.dit: no evidence."
echo "  Imaging PHI (SRV-FILE-01 \\shared\\imaging, ~$(invl SRV-FILE-01 | grep -m1 -oE '~ [0-9 ]+ patients' | tr -dc 0-9) patients) - NO EVIDENCE."
echo

echo "REGULATORY ASSESSMENT:"
tot=$(( r1 + r2 ))
disc=$(grep -m1 -oE 'Discovery date: today[^)]*\([0-9-]+' "$NOTES" | grep -oE '20[0-9-]+'); disc=${disc:-${iso%% *}}
dl=$(date -u -d "$disc +60 days" +%F); early=$(date -u -d "$disc +30 days" +%F)
cohort=$(tr '\n' ' ' < "$INV" | grep -m1 -oE 'approximately [0-9 ]+ - [0-9 ]+ individuals' | sed 's/approximately //; s/ individuals//; s/ \([0-9]\{3\}\)/,\1/g'); est=$(grep -m1 -oE 'Working\s+estimate: [0-9-]+ thousand unique' "$NOTES" | grep -oE '[0-9]+-[0-9]+' ); [ -z "$est" ] && est=$(grep -oE '[0-9]{2}-[0-9]{2} thousand unique' "$NOTES" | head -1 | grep -oE '^[0-9-]+')
echo "  HIPAA breach notification threshold: MET."
echo "  Basis: PHI ($(num "$r1") patients: name, DOB, SSN column, diagnosis codes) was read with valid DB credentials and transmitted to attacker infrastructure ($dst);"
echo "         45 CFR 164.402 presumes a breach, and nothing in the evidence supports a 'low probability of compromise'. $(num "$tot") records exceed the 500-individual tier."
echo "  Scope: $(num "$tot") exported rows (+ $(num "$r3") AD accounts, not PHI). Unique individuals not yet known: inventory estimates ${cohort:-?}, IR notes ${est:-?} thousand (the two estimates conflict); Legal's cross-database join decides."
echo "  Clocks: discovery $disc -> HHS/individual notice by $dl (60 d). IR notes say the state clocks are 30/45/60 days yet quote one date; the 30-day clock would end $early."
echo "         Risk: discovery is when the breach was known or should have been known; if the 04-22 Run-key alert (rule 100091) fired and was missed, the date moves earlier (60 d -> $(date -u -d '2026-04-22 +60 days' +%F))."
echo "  Mitigating factors:"
echo "    [*] SSN encrypted at rest (inventory, since 2025-Q4): does NOT help here - the data was read through an authorised service account; whether the exported ssn values were ciphertext is unverified. No encryption safe harbour."
echo "    [*] Access controls: svc_healthsync is an authorised user of SRV-HEALTH-DB (inventory), so the controls did not block it; the failure was credential theft + unrestricted cross-VLAN reach."
echo "    [*] Response: $(dur $(( $(ep "$iso") - $(ep "$fb") ))) from the first upload to isolation, $(dur $(( $(ep "$iso") - $(ep "$(grep -m1 'First MedDefense contact' "$(ls "$BASE"/previous_findings/4x00*.txt)" | grep -oE '20[0-9-]+') 00:00") ))) from first phishing contact; every staged file was already sent. Not a mitigation."
echo "    [*] Integrity: IR notes say the DBs were read, not modified; unverified (servers not imaged, SQL audit logs not examined)."
echo "  Recommended action: NOTIFY (HHS, individuals, state regulators per the shortest clock); in parallel: pull SQL Server audit logs / images from SRV-HEALTH-DB and SRV-INS-DB, confirm the host-IP mapping,"
echo "  verify whether exported SSNs were ciphertext, finish the de-duplicated individual count, check SRV-FILE-01 and the DC for access, and rotate svc_healthsync, records03 and any DC-held secrets."
echo
bar
