#!/bin/bash

set -euo pipefail

export CAPSTONE_PACK="${CAPSTONE_PACK:-$HOME/evidence_pack_secondary}"
export ASSETS_DIR="${ASSETS_DIR:-$HOME/3x05_assets/capstone_pack/meta}"
export WAZUH_EXPORTS="${WAZUH_EXPORTS:-$HOME/3x05_assets/wazuh_exports}"
export SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
export HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
export PIPELINE_BIN="${PIPELINE_BIN:-$HOME/bt/3x00/pipeline/run_pipeline.sh}"
export BASELINE_BIN="${BASELINE_BIN:-$HOME/bt/3x01/baseline/build_baseline.sh}"
export CATALOG_DIR="${CATALOG_DIR:-$HOME/bt/3x02/catalog}"
export TRIAGE_BIN="${TRIAGE_BIN:-$HOME/bt/3x03/triage/triage.sh}"

fail() {
    echo "[intake] ERROR: $1" >&2
    exit 1
}

declare -A tool_versions

# jq
if command -v jq &>/dev/null; then
    ver=$(jq --version 2>&1 | head -n1 || echo "unknown")
    tool_versions["jq"]="$ver"
    echo "[intake] jq $ver OK"
else
    fail "Missing required binary: jq"
fi

# python3
if command -v python3 &>/dev/null; then
    ver=$(python3 --version 2>&1 | awk '{print $2}' || echo "unknown")
    tool_versions["python3"]="$ver"
    echo "[intake] python3 $ver OK"
else
    fail "Missing required binary: python3"
fi

# yq
if command -v yq &>/dev/null; then
    ver=$(yq --version 2>&1 | awk '{print $NF}' || echo "unknown")
    tool_versions["yq"]="$ver"
    echo "[intake] yq $ver OK"
else
    fail "Missing required binary: yq"
fi

# sigma / sigma-cli
if command -v sigma &>/dev/null; then
    ver=$(sigma --version 2>&1 | awk '{print $NF}' || echo "installed")
    tool_versions["sigma-cli"]="$ver"
    echo "[intake] sigma-cli $ver OK"
elif command -v sigma-cli &>/dev/null; then
    ver=$(sigma-cli --version 2>&1 | awk '{print $NF}' || echo "installed")
    tool_versions["sigma-cli"]="$ver"
    echo "[intake] sigma-cli $ver OK"
else
    fail "Missing required binary: sigma (sigma-cli). Install via: pip install --user sigma-cli"
fi

# sha256sum
if command -v sha256sum &>/dev/null; then
    tool_versions["sha256sum"]="present"
    echo "[intake] sha256sum OK"
else
    fail "Missing required binary: sha256sum"
fi

if [[ -x "$PIPELINE_BIN" ]]; then
    echo "[intake] PIPELINE_BIN OK"
else
    fail "PIPELINE_BIN not found or not executable: $PIPELINE_BIN"
fi

if [[ -x "$BASELINE_BIN" ]]; then
    echo "[intake] BASELINE_BIN OK"
else
    fail "BASELINE_BIN not found or not executable: $BASELINE_BIN"
fi

if [[ -d "$CATALOG_DIR" ]]; then
    rule_count=$(find "$CATALOG_DIR" -maxdepth 1 -name "*.yml" | wc -l)
    if [[ "$rule_count" -gt 0 ]]; then
        echo "[intake] CATALOG_DIR OK ($rule_count rules)"
    else
        fail "CATALOG_DIR contains no .yml rules: $CATALOG_DIR"
    fi
else
    fail "CATALOG_DIR is not a readable directory: $CATALOG_DIR"
fi

if [[ -x "$TRIAGE_BIN" ]]; then
    echo "[intake] TRIAGE_BIN OK"
else
    fail "TRIAGE_BIN not found or not executable: $TRIAGE_BIN"
fi

if [[ -d "$CAPSTONE_PACK" ]]; then
    echo "[intake] CAPSTONE_PACK OK"
else
    fail "CAPSTONE_PACK directory not found: $CAPSTONE_PACK"
fi

required_assets=("assets.json" "ioc_feed.json" "hc_red7_advisory.md" "change_tickets.json" "prior_shift_notes.md")
for f in "${required_assets[@]}"; do
    if [[ ! -f "$ASSETS_DIR/$f" ]]; then
        fail "Missing required asset file: $ASSETS_DIR/$f"
    fi
done
echo "[intake] ASSETS_DIR: 5 meta files OK"

required_wazuh=("incident_A_search_results.json" "incident_B_search_results.json" "incident_C_search_results.json" "campaign_dashboard_summary.md")
for f in "${required_wazuh[@]}"; do
    if [[ ! -f "$WAZUH_EXPORTS/$f" ]]; then
        fail "Missing required Wazuh export file: $WAZUH_EXPORTS/$f"
    fi
done
echo "[intake] WAZUH_EXPORTS: 4 export files OK"

ioc_count=$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")
echo "[intake] ioc_feed.json OK ($ioc_count entries)"

advisory_cluster_id=$(grep -o "HC-RED7" "$ASSETS_DIR/hc_red7_advisory.md" | head -n1 || echo "HC-RED7")
echo "[intake] advisory $advisory_cluster_id loaded"

mkdir -p "$SHIFT_WORKSPACE"/{runtime,enriched,alerts,investigations,campaign,reports,response,handoff}

touch "$SHIFT_WORKSPACE/MANIFEST.json"
touch "$SHIFT_WORKSPACE/runtime/shift_start.json"
touch "$SHIFT_WORKSPACE/runtime/pipeline_run.json"
touch "$SHIFT_WORKSPACE/runtime/baseline_run.json"
touch "$SHIFT_WORKSPACE/runtime/catalog_run.json"

touch "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
touch "$SHIFT_WORKSPACE/enriched/timeline.jsonl"
touch "$SHIFT_WORKSPACE/enriched/baseline.json"
touch "$SHIFT_WORKSPACE/enriched/source_stats.json"

touch "$SHIFT_WORKSPACE/alerts/alert_queue.json"
touch "$SHIFT_WORKSPACE/alerts/shift_briefing.json"
touch "$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
touch "$SHIFT_WORKSPACE/alerts/incidents.json"

touch "$SHIFT_WORKSPACE/investigations/incident_A.json"
touch "$SHIFT_WORKSPACE/investigations/incident_B.json"
touch "$SHIFT_WORKSPACE/investigations/incident_C_cli.json"
touch "$SHIFT_WORKSPACE/investigations/incident_C_export.json"

touch "$SHIFT_WORKSPACE/campaign/campaign_assessment.json"

touch "$SHIFT_WORKSPACE/reports/incident_A.md"
touch "$SHIFT_WORKSPACE/reports/incident_B.md"
touch "$SHIFT_WORKSPACE/reports/incident_C.md"

touch "$SHIFT_WORKSPACE/response/tuning_recommendations.json"
touch "$SHIFT_WORKSPACE/response/containment.json"
touch "$SHIFT_WORKSPACE/response/ioc_package.json"

touch "$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"

shift_id="SHIFT-$(date -u +%Y%m%d-%H%M)"
analyst_host="$(hostname)"
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
resolved_capstone_pack="$(realpath "$CAPSTONE_PACK")"

cat << EOF > "$SHIFT_WORKSPACE/runtime/shift_start.json"
{
  "shift_id": "$shift_id",
  "analyst_host": "$analyst_host",
  "started_at": "$started_at",
  "tools": {
    "jq": "${tool_versions["jq"]}",
    "python3": "${tool_versions["python3"]}",
    "yq": "${tool_versions["yq"]}",
    "sigma-cli": "${tool_versions["sigma-cli"]}",
    "sha256sum": "${tool_versions["sha256sum"]}"
  },
  "prior_project_bins": {
    "pipeline": true,
    "baseline": true,
    "catalog": true,
    "triage": true
  },
  "capstone_pack": "$resolved_capstone_pack",
  "ioc_feed_count": $ioc_count,
  "advisory_cluster_id": "$advisory_cluster_id",
  "wazuh_exports_verified": true
}
EOF

echo "[intake] shift_start.json written"
exit 0
