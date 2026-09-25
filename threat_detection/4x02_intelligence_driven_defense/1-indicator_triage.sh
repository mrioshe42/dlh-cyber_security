#!/bin/bash
# Name: 1-indicator_triage.sh

INPUT_JSON="commercial_feed_extract.json"

total=0
actionable=0
contextual=0
noise=0

while IFS=$'\t' read -r category itype val conf justification uncertainty; do
    ((total++))
    case "$category" in
        ACTIONABLE) ((actionable++)) ;;
        CONTEXTUAL) ((contextual++)) ;;
        NOISE)      ((noise++))      ;;
    esac
    
    printf "[%02d] Type: %-7s | Value: %s\n" "$total" "$(echo "$itype" | tr '[:lower:]' '[:upper:]')" "$val"
    printf "     Source: Commercial Feed     | Category: %s\n" "$category"
    printf "     Conf:   %-15s | Uncertainty: %s\n" "${conf}%" "$uncertainty"
    printf "     Reason: %s\n" "$justification"
done < <(jq -r '
  .indicators[] |
  (.type // "unknown") as $t |
  (.value // "") as $v |
  (.acme_confidence // 50) as $conf |
  (.tags // []) as $tags |
  (.acme_note // "") as $note |
  
  if ($conf < 30 or ($tags | any(. == "cdn-shared" or . == "microsoft-cloud" or . == "cloudflare")) or ($note | test("DO NOT BLOCK"; "i"))) then
    "NOISE\t" + $t + "\t" + $v + "\t" + ($conf|tostring) + "\tShared cloud/CDN infrastructure or low confidence; high false positive risk.\tHigh (Infrastructure shared with benign services)"
  elif (($conf >= 30 and $conf < 75) or ($tags | any(. == "healthcare-kw" or . == "clustered_by_similarity" or . == "POSSIBLE_VITALSCORE_PRIOR" or . == "shared-hosting")) or ($note | test("Predates"; "i"))) then
    "CONTEXTUAL\t" + $t + "\t" + $v + "\t" + ($conf|tostring) + "\tHistorical, pre-campaign staging, or weak similarity match; use for hunting.\tMedium (Requires manual correlation)"
  else
    "ACTIONABLE\t" + $t + "\t" + $v + "\t" + ($conf|tostring) + "\tConfirmed active campaign artifact; safe for perimeter blocklist.\tLow (High confidence corroboration)"
  end
' "$INPUT_JSON")

act_pct=$(awk -v a="$actionable" -v t="$total" 'BEGIN { printf "%.2f", t ? (a/t)*100 : 0 }')
ctx_pct=$(awk -v c="$contextual" -v t="$total" 'BEGIN { printf "%.2f", t ? (c/t)*100 : 0 }')
noi_pct=$(awk -v n="$noise" -v t="$total" 'BEGIN { printf "%.2f", t ? (n/t)*100 : 0 }')

printf "Total Indicators Reviewed : %d\n" "$total"
printf "ACTIONABLE                : %d (%s%%)\n" "$actionable" "$act_pct"
printf "CONTEXTUAL                : %d (%s%%)\n" "$contextual" "$ctx_pct"
printf "NOISE                     : %d (%s%%)\n" "$noise" "$noi_pct"
