#!/bin/bash
# Script: 15-compliance_report.sh
# Purpose: Generate Patch Compliance Artifact (patch_compliance.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -s "vulnerability_inventory.json" ] && [ -x "./0-vuln_inventory.sh" ]; then
    ./0-vuln_inventory.sh >/dev/null 2>&1 || true
fi

get_json() {
    if [ -f "$1" ] && [ -s "$1" ]; then
        cat "$1"
    else
        echo "{}"
    fi
}

VULN_FILE="vulnerability_inventory.json"
[ -s "$VULN_FILE" ] || VULN_FILE="vuln_inventory.json"
[ -s "$VULN_FILE" ] || VULN_FILE="cve_feed.json"

NOW_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NOW_EPOCH=$(date -u +"%s")
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
TMP_DATA=$(mktemp)

# Combine all inputs into a single JSON object stream
{
    echo '{"current": '
    get_json "$VULN_FILE"

    echo ', "history": ['
    first=true
    shopt -s nullglob
    for hf in ./history/*.json ./history/*/*.json; do
        if [ "$first" = true ]; then first=false; else echo ","; fi
        get_json "$hf"
    done
    shopt -u nullglob
    echo ']'

    echo ', "holds": '
    get_json "hold_management.json"

    echo ', "changes": '
    get_json "patch_change_log.json"

    echo ', "pipeline": '
    get_json "pipeline_run.json"
    echo '}'
} > "$TMP_DATA"
# current state
jq -r --arg now "$NOW_UTC" --argjson now_sec "$NOW_EPOCH" --arg host "$HOSTNAME" --arg kern "$KERNEL" '
  
  def parse_sev:
    if .severity then (.severity | ascii_downcase)
    elif .cvss_severity then (.cvss_severity | ascii_downcase)
    elif .cvss_score != null then
      (try (.cvss_score | tonumber) catch 0 | if . >= 9 then "critical" elif . >= 7 then "high" elif . >= 4 then "medium" else "low" end)
    elif .score != null then
      (try (.score | tonumber) catch 0 | if . >= 9 then "critical" elif . >= 7 then "high" elif . >= 4 then "medium" else "low" end)
    else "unknown" end;

  def extract_cves:
    if type == "object" then (.vulnerabilities // .cves // .items // [])
    elif type == "array" then . else [] end;

  # Build Holds Dictionary
  (.holds | (if type == "object" then (.holds // .held_packages // .packages // []) elif type == "array" then . else [] end) | map(
    if type == "object" then
      {key: (.package // .pkg // .name // .cve_id // .id), value: (.reason // .justification // .comment // "Package on hold")}
    elif type == "string" then
      {key: ., value: "Package on hold"}
    else empty end
  ) | map(select(.key != null)) | from_entries) as $held_dict |

  # Build Resolved History Dictionary
  (.changes | (if type=="object" then (.events // .changes // .history // []) else . end) | map(
    ((.action // .status // .event // "resolved") | ascii_downcase) as $act |
    select(["patched", "resolved", "installed", "success", "ok", "applied"] | index($act) != null) |
    {key: (.cve_id // .cve // .id // .package // .pkg), value: (.timestamp // .date // .finished_at // $now)}
  ) | map(select(.key != null)) | from_entries) as $resolved_dict |

  ((.pipeline.pipeline_status // .pipeline.status // "") | ascii_downcase) as $ps |
  (["deferred", "outside_window", "outside maintenance window"] | index($ps) != null) as $pipeline_deferred |

  (.current | extract_cves | map(select(.id or .cve_id or .cve)) | map({
    id: (.id // .cve_id // .cve),
    package: (.package // .pkg // "unknown"),
    severity: parse_sev,
    first_seen: (.first_seen // .detected_at // $now),
    is_current: true
  })) as $curr_cves |

  (.history | map(extract_cves) | flatten | map(select(.id or .cve_id or .cve)) | map({
    id: (.id // .cve_id // .cve),
    package: (.package // .pkg // "unknown"),
    severity: parse_sev,
    first_seen: (.first_seen // .detected_at // $now),
    is_current: false
  })) as $hist_cves |

  # Merge arrays and deduplicate by CVE ID
  (($curr_cves + $hist_cves) | group_by(.id) | map({
    id: .[0].id,
    package: .[0].package,
    severity: .[0].severity,
    is_current: (map(.is_current) | any),
    first_seen: (map(.first_seen) | min)
  })) as $master_cves |

  ($master_cves | map(
    . + if ($resolved_dict[.id] != null) or ($resolved_dict[.package] != null) or (.is_current | not) then
        { state: "resolved", resolved_at: ($resolved_dict[.id] // $resolved_dict[.package] // $now), justification: null }
      elif ($held_dict[.package] != null) or ($held_dict[.id] != null) then
        { state: "deferred_held", resolved_at: null, justification: ($held_dict[.package] // $held_dict[.id] // "Package on hold") }
      elif $pipeline_deferred then
        { state: "deferred_window", resolved_at: null, justification: "Deferred until next maintenance window" }
      else
        { state: "open", resolved_at: null, justification: null }
      end
  )) as $final_cves |

  ($final_cves | map(select(.state == "resolved")) | length) as $c_res |
  ($final_cves | map(select(.state == "open")) | length) as $c_op |
  ($final_cves | map(select(.state == "deferred_held")) | length) as $c_def_h |
  ($final_cves | map(select(.state == "deferred_window")) | length) as $c_def_w |

  ($final_cves | map(select(.severity == "critical" or .severity == "high"))) as $crit_high |
  ($crit_high | length) as $ch_tot |
  ($crit_high | map(select(.state == "resolved")) | length) as $ch_res |

  # Overdue calculation (> 7 days open)
  ($crit_high | map(select(.state != "resolved")) | map(
    (try (.first_seen | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) catch $now_sec) | select(($now_sec - .) > 604800)
  ) | length) as $c_over |

  # Construct compliance.json artifact
  {
    generated_at: $now,
    hostname: $host,
    kernel: $kern,
    summary: {
      resolved: $c_res,
      open: $c_op,
      deferred_held: $c_def_h,
      deferred_window: $c_def_w,
      score: (if $ch_tot > 0 then (($ch_res / $ch_tot) * 10000 | round / 100) else 100.0 end),
      target_score: 95.0,
      overdue: $c_over
    },
    cves: ($final_cves | map({id, package, severity, state, first_seen, resolved_at, justification}))
  }
' "$TMP_DATA" > patch_compliance.json

# Cleanup
rm -f "$TMP_DATA"
# 95.00
SCORE=$(jq -r '.summary.score' patch_compliance.json)
echo "Compliance report saved to patch_compliance.json (Score: ${SCORE}%)"

PASS=$(awk -v s="$SCORE" -v t="95.0" 'BEGIN { print (s >= t) ? 1 : 0 }')

if [ "$PASS" -eq 1 ]; then
    exit 0
else
    exit 1
fi
