#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
P="$BASE/previous_findings"; I="$BASE/ir_evidence"
f00=$(ls "$P"/4x00*.txt); f01=$(ls "$P"/4x01*.txt); f03=$(ls "$P"/4x03*.txt); f02=$(ls "$P"/4x02*.json)
MEM=$(ls "$I"/memory*.txt); DISK=$(ls "$I"/disk*.txt); FW=$(ls "$I"/firewall*.json)
IOC="$BASE/reference/healthbane_ioc_master.json"; NAV="$BASE/reference/attck_navigator_80pct.json"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
ts()  { grep -m1 -E "$2" "$1" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z' | head -1; }   # first ISO stamp on the matching line
ep()  { date -u -d "$1" +%s; }
dur() { awk -v s="$1" 'BEGIN{ if (s<120) printf "%ds", s; else if (s<7200) printf "%dm%02ds", s/60, s%60; else if (s<172800) printf "%dh%02dm", s/3600, (s%3600)/60; else printf "%.1f days", s/86400 }'; }
hm()  { [[ "$1" =~ ^[0-9]+$ ]] && set -- "@$1"; date -u -d "$1" +'%m-%d %H:%M:%SZ'; }
conf() { local n=$1 hi=$2; if [ "$n" -ge 2 ]; then echo "CONFIRMED ($n independent sources)"; elif [ "$n" -eq 1 ] && [ "$hi" = Y ]; then echo "PROBABLE (single source)"; else echo "POSSIBLE (inference)"; fi; }

ev() { printf '  [%s] %s\n    Evidence: %s\n    Technique: %s | Confidence: %s%s\n' "$(hm "$1")" "$2" "$3" "$4" "$(conf "$5" Y)" "${6:+ | $6}"; }
TECH=""

tmail=$(ts "$f01" '^\[T-001\]'); tclick=$(ts "$f00" 'At 20[0-9-]+T[0-9:]+Z'); tpost=$(ts "$f01" '^\[T-004\]')
[ -z "$tclick" ] && tclick=$(ts "$f01" '^\[T-002\]')
n_all=$(grep -oE 'Total emails analyzed: +[0-9]+' "$f00" | grep -oE '[0-9]+$'); n_bad=$(grep -oE 'Emails confirmed malicious: +[0-9]+' "$f00" | grep -oE '[0-9]+$')
e1=$(awk '/^\[E1\]/{f=1} f&&/^\[E2\]/{exit} f' "$f00")
spf=$(grep -m1 'SPF:' <<< "$e1" | awk '{print $2}'); dkim=$(grep -m1 'DKIM:' <<< "$e1" | awk '{print $2}'); dmarc=$(grep -m1 'DMARC:' <<< "$e1" | awk '{print $2}')
rcpt=$(grep -m1 'Recipients:' <<< "$e1" | grep -oE '[0-9]+' | head -1); sender=$(grep -m1 'Sender:' <<< "$e1" | awk '{print $2}')
reg=$(jq -r '.iocs[] | select(.value=="meddefense-portal.com") | .evidence_paths[]' "$IOC" | grep -m1 -oE 'registered [0-9-]+' | awk '{print $2}')
post_b=$(grep -A3 '^\[T-004\]' "$f01" | grep -m1 -oE 'Bytes: [0-9]+' | awk '{print $2}'); host=$(grep -m1 -oE 'WS-RECV-[0-9]+' "$f01")
rot=$(grep -m1 -oE 'rotated dmarsh.s password at [0-9:]+Z' "$f00" | grep -oE '[0-9:]+Z'); rev=$(grep -m1 -oE 'force-revoked in Azure AD at [0-9:]+Z' "$f00" | grep -oE '[0-9:]+Z')
rep=$(grep -m1 -oE 'helpdesk at [0-9:]+Z' "$f00" | grep -oE '[0-9:]+Z'); d=${tpost%%T*}
claim=$(grep -m1 -oE '[0-9]+-minute window' "$f00" | grep -oE '^[0-9]+')

bar
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
bar
echo
echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "  Timeline: Week 11, $(grep -m1 'Investigation period' "$f00" | grep -oE '20[0-9-]+' | paste -sd' ' | sed 's/ / to /') (campaign first contact $(grep -m1 'First MedDefense contact' "$f00" | grep -oE '20[0-9-]+'))"
echo
ev "$(ep "${reg:-$d}")" "Lookalike infrastructure registered (meddefense-portal.com, Let's Encrypt cert same day)" \
   "4x00 sandbox/cert, IOC master WHOIS (registered ${reg}, $(( ($(ep "$tmail") - $(ep "$reg")) / 86400 )) days before delivery)" "T1583.001 Acquire Domains" 2
ev "$(ep "$tmail")" "Campaign emails delivered ($n_all analysed, $n_bad malicious; E1 '$sender' to $rcpt staff)" \
   "4x00 headers: SPF $spf, DKIM $dkim, DMARC $dmarc; 4x01 T-001 SMTP capture" "T1566.002 Spearphishing Link" 2
ev "$(ep "$tclick")" "$(grep -m1 -oE 'Diane Marsh' "$f00") ($host, dmarsh) clicks the credential-harvesting link" \
   "4x00 browser history + Azure AD telemetry; 4x01 T-002/T-003 DNS+TLS to portal" "T1566.002 -> lookalike O365 login" 2
ev "$(ep "$tpost")" "Credentials submitted to attacker-controlled /collect.php (${post_b} B POST, 302 to login.microsoft.com)" \
   "4x00 domain analysis; 4x01 T-004 PCAP POST" "T1078 Valid Accounts (obtained, not shown used)" 2 "temporal anchor"
ev "$(ep "$d ${rot%Z}")" "Password rotated $rot, sessions revoked $rev (helpdesk report $rep)" "4x00 only" "-" 1
TECH+=" T1583.001 T1566.002 T1078"

t6=$(ts "$f01" '^\[T-006\]'); t7=$(ts "$f01" '^\[T-007\]'); t8=$(ts "$f01" '^\[T-008\]'); t9=$(ts "$f01" '^\[T-009\]'); tend=$(ts "$f01" '^\[T-299\]')
size=$(grep -m1 -oE 'PE32\+ executable, [0-9 ]+ bytes' "$f03" | grep -oE '[0-9 ]+ bytes' | tr -d ' bytes'); dsz=$(grep -A1 -m1 'svchost_update.exe$' "$DISK" | grep -m1 -oE '[0-9 ]{7,} bytes' | tr -d ' bytes')
c2ip=$(grep -A4 '^\[T-008\]' "$f01" | grep -m1 'Destination' | grep -oE '([0-9]+\.){3}[0-9]+'); sni=$(grep -m1 'SNI: sync' "$f01" | awk '{print $2}')
ja3=$(grep -m1 -oE 'JA3 hash: +[0-9a-f]{32}' "$f01" | grep -oE '[0-9a-f]{32}'); fwja3=$(jq -r '.summary.by_classification.KNOWN_C2.ja3_observed' "$FW")
fwn=$(jq '.summary.by_classification.KNOWN_C2.session_count' "$FW"); fwfirst=$(jq -r '.summary.by_classification.KNOWN_C2.first_seen_in_window' "$FW"); fwlast=$(jq -r '.summary.by_classification.KNOWN_C2.last_seen_in_window | split(" ")[0]' "$FW")
fwrows=$(jq -r '[.sessions[]? | select(.session_id and .classification=="KNOWN_C2")] | "\(length) \(.[0].ts_start) \(.[1].ts_start) \(.[0].bytes_out) \(.[0].bytes_in)"' "$FW"); read -r nrow r0 r1 fbo fbi <<< "$fwrows"
fgap=$(( $(ep "$r1") - $(ep "$r0") )); pb_out=$(grep -A6 '^\[T-009\]' "$f01" | grep -m1 -oE 'Outbound: [0-9]+' | awk '{print $2}'); pb_in=$(grep -A6 '^\[T-009\]' "$f01" | grep -m1 -oE 'Inbound: [0-9]+' | awk '{print $2}')
skew=$(jq -r '.metadata._notes | join(" ")' "$FW" | grep -oE 'are [0-9]+ seconds' | grep -oE '[0-9]+')
k1=$(sed -n '/^\[K1\]/,/^\[K2\]/p' "$MEM" | grep -m1 'Last Write' | grep -oE '20[0-9-]+ [0-9:]+' | head -1); k1=${k1/ /T}Z
av=$(grep -A1 'AV detection on' "$f03" | grep -m1 -oE '20[0-9]{2}-[0-9-]+')

echo
echo "STAGE 2: C2 ESTABLISHMENT"
echo "  Timeline: $(hm "$t6" | cut -c1-5), $(dur $(( $(ep "$t9") - $(ep "$tpost") ))) after the credential theft, $(dur $(( $(ep "$t9") - $(ep "$t6") ))) after the second-wave mail"
echo
ev "$(ep "$t6")" "Second-wave mail with macro dropper (April-Invoice-MD2026.docm) released from quarantine by helpdesk" \
   "4x01 T-006 SMTP; 4x03 S1 (opened copy in Diane's mailbox)" "T1566.001 Spearphishing Attachment" 2 "this, not the stolen password, is the foothold"
ev "$(ep "$t8")" "Macro runs: DNS ${t7##*T} then HTTPS GET /update/svchost_update.exe from $c2ip ($(dur $(( $(ep "$t8") - $(ep "$t6") ))) after delivery); RAT ${size} B received" \
   "4x01 T-007/T-008; 4x03 S2 (${size} B); IR-DISK F1 (${dsz} B)" "T1204.002 User Execution, T1059.005 VBA, T1105 Ingress Tool Transfer" 3
ev "$(ep "$t9")" "First C2 beacon to $c2ip:443 (SNI $sni, POST /api/v1/checkin, ${pb_out} B out / ${pb_in} B in)" \
   "4x01 T-009 (PCAP); 4x03 S2 beacon design + RC4 key; firewall clock runs ${skew}s ahead of PCAP (same beacon = $(hm $(( $(ep "$t9") + skew )) | cut -c7-) on the firewall)" "T1071.001 Web Protocols, T1573.001 Symmetric Crypto (RC4)" 2 "no firewall data exists for 04-15"
exp=$(( ($(ep "$tend") - $(ep "$t9")) / 304 )); got=$(grep -oE '[0-9]+ additional C2 beacons' "$f01" | grep -oE '^[0-9]+')
rk=$(( $(ep "$k1") - $(ep "$t9") ))
ev "$(ep "$k1")" "RAT (re)installed on the host with Run-key: file born $(grep -A5 -m1 'svchost_update.exe$' "$DISK" | grep -m1 ' B: ' | grep -oE '[0-9:]{8}') UTC, $(dur $(( $(ep "$k1") - $(ep "$(awk '/Boot time/{print $3"T"$4"Z"}' "$MEM" | head -1)") ))) after the reboot; $(dur "$rk") after first beacon" \
   "IR-MEM K1 Run-key write; IR-DISK F1/R1; 4x03 S2 (Run-key by design)" "T1547.001 Registry Run Keys" 2 "AV quarantined S2 on ${av}; how it returned is unexplained"
ev "$(ep "$fwfirst")" "C2 pattern: 300 s jittered HTTPS beacons, continuous $(hm "$fwfirst" | cut -c1-5) -> $(hm "$fwlast" | cut -c1-5) ($fwn firewall sessions); JA3 $( [ "$ja3" = "$fwja3" ] && echo "identical" || echo "DIFFERENT") in PCAP and firewall" \
   "4x01 beacon fingerprint; IR-FW KNOWN_C2 (first rows ${fgap}s apart, ${fbo} B out / ${fbi} B in per session incl. TLS handshake); IR-MEM netscan (live session at capture)" "T1071.001" 3
ev "$(ep "$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window' "$FW")")" "Secondary C2 first seen: $(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0]' "$FW") ($(dur $(( $(ep "$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window' "$FW")") - $(ep "$t9") ))) after Stage 2)" \
   "IR-FW only for timing (14 sessions, ~daily); IR-MEM netscan shows it live; absent from 4x01 (PCAP ended $(hm "$tend" | cut -c1-5))" "T1571 Non-Standard Port, T1071.001" 2 "role = fallback C2 is an inference"
TECH+=" T1566.001 T1204.002 T1059.005 T1105 T1071.001 T1573.001 T1547.001 T1571"

echo
echo "DISCREPANCIES RESOLVED:"
[ -n "$claim" ] && echo "  - 4x00 says a $claim-minute exposure window, but its own times give $(dur $(( $(ep "$d ${rot%Z}") - $(ep "$tpost") ))) to rotation / $(dur $(( $(ep "$d ${rev%Z}") - $(ep "$tpost") ))) to revocation; $claim min is the delay to the helpdesk report ($rep). Use the timestamps."
echo "  - 4x01 counts $got beacons after T-009 but only $(dur $(( $(ep "$tend") - $(ep "$t9") ))) of PCAP remain (~$exp at 304 s; $got equals a full 24 h at 5 min). Count is unreliable; interval and JA3 are corroborated by the firewall."
echo "  - Stage 2 began $(dur $(( $(ep "$t9") - $(ep "$tpost") ))) after the credential theft via a different mail, and 4x00/4x01 saw no logon as dmarsh: the harvested credential is not the foothold (T1078 = obtained only)."
echo "  - Technique IDs: the credential link is T1566.002 and the .docm is T1566.001 (the layer's own T1566.001 comment says 'link')."
echo "  - T1568 Dynamic Resolution: not supported. $(grep -oE '(update|sync|data-sync)\.healthbane-c2\.net' "$f01" | sort -u | wc -l) fixed C2 domains resolve to $(jq -r '.iocs[] | select(.type=="ipv4") | .value' "$IOC" | paste -sd' '), no DGA/fast-flux seen; the secondary IP had no DNS lookup (IR-MEM), so it arrived as a C2 directive."

echo
echo "STAGE 1-2 SUMMARY:"
echo "  Duration: $(dur $(( $(ep "$t9") - $(ep "$tmail") ))) from first phishing mail to first C2 beacon ($(dur $(( $(ep "$t9") - $(ep "$t6") ))) from the dropper mail)"
tl=""; for t in $(tr ' ' '\n' <<< "$TECH" | sort -u); do s=$(jq -r --arg t "$t" '[.techniques[] | select(.techniqueID==$t) | .comment | split(" ")[0]] | first // "NEW"' "$NAV"); tl+="$t($s) "; done
echo "  Techniques mapped (Navigator state): $tl"
indep=" 4x00 4x01 4x03 4x04 "; conv=0; one=0; tot=0
while IFS=$'\t' read -r v; do tot=$((tot + 1)); n=0
    for src in "$f00" "$f01" "$f03" "$(ls "$P"/4x04*.txt)" "$MEM" "$DISK" "$FW"; do grep -qiF -- "${v:0:32}" "$src" && n=$((n + 1)); done
    [ "$n" -ge 2 ] && conv=$((conv + 1)) || one=$((one + 1)); done < <(jq -r '.iocs[] | select(.first_seen <= "2026-04-21" and (.type|test("domain|ipv4|filename|sha256|user_account"))) | .value' "$IOC")
echo "  IOCs from this period (first seen <= 04-21): $tot (converged: $conv, single-source: $one)"
sec=$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0]' "$FW")
echo "  Key finding: no evidence the secondary C2 ($sec) existed during Stage 2 (04-15), but the firewall only starts $(hm "$fwfirst" | cut -c1-5):"
echo "  04-16 -> 05-01 is unobserved, so 'not operational' cannot be claimed. First seen $(dur $(( $(ep "$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window' "$FW")") - $(ep "$k1") ))) after the RAT reinstall, and $(( $(ep "$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.first_seen_in_window' "$FW")") - $(ep "$(sed -n '/^\[K2\]/,/^\[K3\]/p' "$MEM" | grep -m1 'Last Write' | grep -oE '20[0-9-]+ [0-9:]+' | head -1 | sed 's/ /T/')Z") )) s after the scheduled task was written (05-07)."
echo
bar
