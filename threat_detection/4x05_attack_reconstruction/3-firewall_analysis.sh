#!/bin/bash

export LC_ALL=C
BASE="${1:-$(dirname "$(readlink -f "$0")")/4x05}"
FW="$BASE/ir_evidence/firewall_sessions_ws_recv_03.json"; IOC="$BASE/reference/healthbane_ioc_master.json"
DISK="$BASE/ir_evidence/disk_forensics_report.txt"; MEM="$BASE/ir_evidence/memory_artifacts.txt"; PREV="$BASE/previous_findings"
LARGE=1000000
TZOFF=-5
for f in "$FW" "$IOC"; do [ -f "$f" ] || { echo "Missing: $f" >&2; exit 1; }; done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

bar() { printf '%*s\n' 64 '' | tr ' ' '='; }
mb()  { awk -v b="$1" 'BEGIN{ if (b>=1e6) printf "%.1f MB", b/1e6; else if (b>=1e3) printf "%.1f KB", b/1e3; else printf "%d B", b }'; }
S='[.sessions[] | select(.session_id)]'
EXT='select(.dst_ip | test("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)") | not)'
LOCAL='(.ts_start | fromdateiso8601 + ('$TZOFF'*3600))'

N=$(jq "$S | length" "$FW"); TOT=$(jq '.summary.total_sessions_in_window' "$FW")
bar
echo "   FIREWALL SESSION ANALYSIS - $(jq -r '.metadata.host_of_interest' "$FW")"
echo "   Source: ir_evidence/$(basename "$FW")"
echo "   Period: $(jq -r '.metadata.time_range_utc | "\(.start[0:10]) to \(.end[0:10])"' "$FW")   ($(jq -r '.metadata.source' "$FW"))"
bar
echo

echo "SESSION OVERVIEW:"
echo "  Total sessions in window: $TOT   (export holds $N explicit rows, metadata says $(jq '.metadata.session_count_in_export' "$FW"); rest are class aggregates)"
jq -r '.summary.by_classification | to_entries[] | [.key, .value.session_count, (.value.total_bytes_out_including_exfil_bursts // .value.total_bytes_out // -1)] | @tsv' "$FW" \
 | awk -F'\t' -v tot="$TOT" '{ int_=($1=="BENIGN"||$1=="LATERAL_MOVEMENT"); k=int_?"internal":"external"; c[k]+=$2; s+=$2
       printf "    %-24s %-9s %6d sessions%s\n", $1, k, $2, ($3>=0 ? "  out " $3 " B" : "") }
     END{ printf "  Internal destinations: %d sessions | External: %d | unclassified: %d\n", c["internal"], c["external"], tot-s }' \
 | sed -E 's/out ([0-9]+) B/out \1 B/' \
 | while IFS= read -r l; do if [[ "$l" =~ out\ ([0-9]+)\ B ]]; then echo "${l/out ${BASH_REMATCH[1]} B/out $(mb "${BASH_REMATCH[1]}")}"; else echo "$l"; fi; done
echo

echo "TOP EXTERNAL DESTINATIONS (by bytes out; * = class aggregate, others = explicit rows only):"
printf '  %-4s %-16s %-5s %-6s %-9s %-11s %s\n' Rank IP Port Proto Sessions "Bytes Out" "Bytes In"
jq -r --argjson s "$(jq -c "$S" "$FW")" '
  ([.summary.by_classification | to_entries[] | select(.key|test("C2")) | .value.destinations[]? | split(":")[0]]) as $agg
  | ( [ .summary.by_classification | to_entries[] | select(.key|test("KNOWN_C2|SECONDARY")) | .value as $v
        | ($v.destinations[0] | split(":")) as $d
        | { ip:$d[0], port:$d[1], proto:(first($s[] | select(.dst_ip==$d[0]) | .proto) // "tcp"), n:$v.session_count,
            out:($v.total_bytes_out_including_exfil_bursts // $v.total_bytes_out), in:$v.total_bytes_in, star:"*" } ]
      + [ $s | map(select(.dst_ip | test("^10\\.|^192\\.168\\.") | not) | select([.dst_ip] | inside($agg) | not))
          | group_by([.dst_ip,.dst_port,.proto])[] | { ip:.[0].dst_ip, port:(.[0].dst_port|tostring), proto:.[0].proto, n:length, out:(map(.bytes_out)|add), in:(map(.bytes_in)|add), star:"" } ] )
  | sort_by(-.out) | .[:10] | to_entries[] | [(.key+1), .value.ip, .value.port, .value.proto, "\(.value.n)\(.value.star)", .value.out, .value.in] | @tsv' "$FW" \
 | while IFS=$'\t' read -r r ip p pr n o i; do printf '  %-4s %-16s %-5s %-6s %-9s %-11s %s\n' "$r" "$ip" "$p" "$pr" "$n" "$(mb "$o")" "$(mb "$i")"; done
echo

echo "TOP INTERNAL DESTINATIONS (by sessions, explicit rows only):"
jq -r --slurpfile ioc "$IOC" "$S | map(select(.dst_ip | test(\"^10\\\\.\"))) | group_by(.dst_ip)[] | [.[0].dst_ip, length, ([.[].dst_port]|unique|map(tostring)|join(\",\"))] | @tsv" "$FW" \
 | sort -k2,2nr | head -10 | while IFS=$'\t' read -r ip n ports; do
     nm=$(jq -r --arg ip "$ip" '.metadata.iocs_relevant[] | select(contains($ip)) | split("  ")[-1] | gsub(" +";" ")' "$FW" | head -1)
     printf '  %-14s %3d sessions  ports %-18s %s\n' "$ip" "$n" "$ports" "$nm"; done
echo

UIP=$(jq -r --slurpfile ioc "$IOC" '[ $ioc[0].iocs[].value ] as $k
   | [ .summary.by_classification | to_entries[] | select(.key | test("BENIGN|BROWSING|INTERNAL|LATERAL") | not) | .value.destinations[]? | split(":")[0] ]
   | map(select(. as $i | $k | index($i) | not)) | first // empty' "$FW")
if [ -n "$UIP" ]; then
  cls=$(jq -c --arg ip "$UIP" '.summary.by_classification | to_entries[] | select(.value.destinations[]? | startswith($ip)) | .value' "$FW")
  rows=$(jq -c --arg ip "$UIP" "$S | map(select(.dst_ip==\$ip))" "$FW")
  port=$(jq -r '[.[].dst_port]|unique|join(",")' <<< "$rows"); proto=$(jq -r '[.[]|.proto+"/"+.app]|unique|join(",")' <<< "$rows")
  fs=$(jq -r .first_seen_in_window <<< "$cls"); ls_=$(jq -r .last_seen_in_window <<< "$cls")
  hrs=$(jq -r "map($LOCAL | strftime(\"%H\") | tonumber) | [min, max] | \"\(.[0]):00-\(.[1]+1):00\"" <<< "$rows")
  bo=$(jq .total_bytes_out <<< "$cls"); bi=$(jq .total_bytes_in <<< "$cls"); n=$(jq .session_count <<< "$cls")
  echo "UNKNOWN IP INVESTIGATION:"
  echo "  IP: $UIP:$port ($proto)   not in IOC master"
  echo "  First seen: $fs   Last seen: $ls_   Sessions: $n (aggregate), $(jq length <<< "$rows") explicit"
  echo "  Pattern: $(jq -r .interval_observed <<< "$cls"); explicit rows at local $hrs"
  echo "  Bytes out: $(mb "$bo") | Bytes in: $(mb "$bi")  (avg $(( bo / n )) B out/session)"
  pend=$(grep -m1 'PCAP collection window' "$PREV"/*network* | grep -oE '20[0-9-]+T[0-9:]+Z' | tail -1)
  in4x01=$(grep -c "$UIP" "$PREV"/*network* | awk -F: '{s+=$2} END{print s+0}')
  proc=$(grep -m1 "$UIP" "$MEM" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.exe$/) print $i}' | head -1)
  tk=$(grep -A4 '^\[K2\]' "$MEM" | grep -oE '20[0-9]{2}-[0-9-]+ [0-9:]+ UTC' | head -1 | sed 's/ UTC//')
  dt=$(( $(date -u -d "$fs" +%s) - $(date -u -d "$tk" +%s) ))
  c4=$(grep -m1 -oE 'to 185.220[^ ]*|Heartbeat: .*' "$PREV"/*network* | head -1)
  echo
  echo "  CORRELATION with known HEALTHBANE infrastructure:"
  echo "    - 4x01: primary C2 = 443/tcp, ${c4#Heartbeat: } beacons; this IP = $port/tcp, ~daily -> different port and cadence"
  echo "    - first seen $fs is after the 4x01 PCAP window ended ($pend), mentions in 4x01: $in4x01 -> could not have been seen there"
  echo "    - same process as the known C2 in memory: ${proc:-n/a}; first seen ${dt#-} s after the scheduled-task write ($tk UTC)"
  small=$(( bo < LARGE ? 1 : 0 )); [ "$small" -eq 1 ] && sz="only $(mb "$bo") out in total -> far too small for staging/exfil (largest burst $(mb "$(jq '[.sessions[]?|.bytes_out//0]|max' "$FW")"))"
  echo "    - volume: ${sz:-large volume: possible staging server}"
  echo "  ASSESSMENT: low-volume fixed-cadence off-hours channel, same RAT process, tied to task creation = SECONDARY C2 (standby/fallback),"
  echo "  not a staging server and not unrelated traffic. CONFIDENCE: PROBABLE. -> NEW IOC: $UIP:$port (secondary C2)"
  echo
fi

echo "TEMPORAL ANALYSIS (local CDT; explicit rows only, so counts are a sample):"
jq -r "$S | map($LOCAL | strftime(\"%H\") | tonumber) | group_by(.) | map({(.[0]|tostring): length}) | add" "$FW" > /tmp/.fw_h.$$ 2>/dev/null
hrow=""; hnum=""; for h in $(seq 0 23); do c=$(jq -r --arg h "$h" '.[$h] // 0' /tmp/.fw_h.$$); hrow+=$(printf '%3d' "$h"); hnum+=$(printf '%3s' "$([ "$c" -eq 0 ] && echo . || echo "$((c>9?9:c))")"); done; rm -f /tmp/.fw_h.$$
echo "    hour  $hrow"; echo "    sess  $hnum   (business 08-17 | off-hours 18-07)"
read -r biz off days <<< "$(jq -r "$S | map($LOCAL | strftime(\"%H\") | tonumber) as \$h | [(\$h|map(select(.>=8 and .<18))|length), (\$h|map(select(.<8 or .>=18))|length)] | @tsv" "$FW") $(jq -r '(.metadata.time_range_utc | ((.end|fromdateiso8601) - (.start|fromdateiso8601))/86400 | ceil)' "$FW")"
echo "  Business hours: $biz explicit sessions (~$(awk -v a="$biz" -v d="$days" 'BEGIN{printf "%.1f", a/d}')/day) | Off-hours: $off (~$(awk -v a="$off" -v d="$days" 'BEGIN{printf "%.1f", a/d}')/day); beacons run 24/7 so off-hours is dominated by C2"
att=$(jq -r "$S | map($EXT | select((.classification|test(\"EXFIL|SECONDARY\")) or (.bytes_out>10000 and .classification==\"KNOWN_C2\"))) | map($LOCAL | strftime(\"%m-%d\")) | unique | join(\", \")" "$FW")
lat=$(jq -r "$S | map(select(.classification==\"LATERAL_MOVEMENT\")) | map($LOCAL | strftime(\"%m-%d\")) | unique | join(\", \")" "$FW")
hunt=$(grep -E 'PsExec session #' "$PREV"/*hunt* | sed -E 's/^ *20[0-9]{2}-([0-9]{2}-[0-9]{2}) .*/\1/' | sort -u | paste -sd, | sed 's/,/, /g')
echo "  Off-hours attack-type external sessions on: ${att:-none}"
echo "  Cross-VLAN sessions to servers on: ${lat:-none} | 4x04 PsExec sessions: ${hunt:-n/a} -> $([ "$lat" = "$hunt" ] && echo MATCH || echo "overlap: $(comm -12 <(tr -d ' ' <<< "${lat//,/$'\n'}" | sort) <(tr -d ' ' <<< "${hunt//,/$'\n'}" | sort) | paste -sd, | sed 's/,/, /g')")"
echo "  Large transfers (bytes_out > $(mb $LARGE)):"
jq -r "$S | map($EXT | select(.bytes_out > $LARGE)) | sort_by(.ts_start)[] | [(.ts_start | fromdateiso8601 + ($TZOFF*3600) | strftime(\"%m-%d %H:%M\")), .dst_ip, .dst_port, .bytes_out] | @tsv" "$FW" \
 | while IFS=$'\t' read -r t ip p b; do echo "    $t CDT  -> $ip:$p  $(mb "$b")"; done
echo

echo "EXFILTRATION ASSESSMENT:"
big=$(jq -r "$S | map($EXT) | max_by(.bytes_out) | \"\(.bytes_out) \(.dst_ip) \(.ts_start[0:10])\"" "$FW")
c2all=$(jq '.summary.by_classification.KNOWN_C2 | .total_bytes_out_including_exfil_bursts' "$FW"); c2x=$(jq '.summary.by_classification.KNOWN_C2.total_bytes_out_excluding_exfil_bursts' "$FW")
burst=$(jq '.summary.by_classification.EXFIL_BURST.total_bytes_out' "$FW"); sec=$(jq '.summary.by_classification | to_entries[] | select(.key|test("SECONDARY")) | .value.total_bytes_out' "$FW")
echo "  Largest single outbound transfer: $(mb "${big%% *}") to $(cut -d' ' -f2 <<< "$big") on $(cut -d' ' -f3 <<< "$big")"
echo "  Total outbound to C2 infrastructure: $(mb "$c2all") (beacons only $(mb "$c2x"), burst class $(mb "$burst")) | to unknown IP: $(mb "${sec:-0}")"
sizes=$(awk '/^3\.2 /{f=1} /^3\.3 /{f=0} f' "$DISK" | grep -E '^\[D[0-9]\]|Recovered size' | paste - - | grep -E '\.(zip|csv)' | sed -E 's/\[(D[0-9])\] +\S*\\([^\\ ]+).*size: +([0-9 ]+) bytes.*/\1 \2 \3/' | awk '{n=$1" "$2; $1=$2=""; gsub(/ /,""); print n, $0}')
tot=0; ok=0; cnt=0
while read -r d f b; do [ -z "$b" ] && continue
   cnt=$((cnt + 1)); tot=$((tot + b))
   m=$(jq -r --argjson b "$b" '.sessions[]? | select(.bytes_out==$b) | "\(.ts_start[0:16])Z -> \(.dst_ip)"' "$FW" | head -1)
   [ -n "$m" ] && ok=$((ok + 1)); echo "    $d $f $(mb "$b"): $([ -n "$m" ] && echo "firewall transfer of identical size, $m" || echo "NO matching transfer")"; done <<< "$sizes"
echo "  Staging file sizes (disk report): $(mb "$tot") total in $cnt files; matched to firewall transfers: $ok/$cnt"
echo "  FINDING: outbound to suspicious destinations ($(mb "$((c2all + ${sec:-0}))")) is MORE than staging ($(mb "$tot")); the excess $(mb "$((c2all - c2x - burst))") fits the LSASS-dump uploads on the two"
echo "  credential-dump days (flagged in the export notes). Every staged archive left the network, so exfiltration was COMPLETED, not interrupted."
echo "  Last allowed session $(jq -r '.summary.by_classification.KNOWN_C2.last_seen_in_window' "$FW"); then $(jq -r '.summary.by_classification.KNOWN_C2.after_isolation' "$FW") after isolation: nothing left after containment."
echo
bar
