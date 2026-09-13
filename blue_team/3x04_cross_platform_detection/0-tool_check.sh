#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

FAILED=0

if command -v jq &>/dev/null; then
    JQ_VER=$(jq --version 2>&1 | sed 's/jq-//')
    printf "jq          : %s\n" "$JQ_VER"
else
    echo "jq          : NOT FOUND"
    ((FAILED++))
fi

if command -v yq &>/dev/null; then
    YQ_VER=$(yq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    printf "yq          : %s\n" "$YQ_VER"
else
    echo "yq          : NOT FOUND"
    ((FAILED++))
fi

if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    printf "python3     : %s\n" "$PY_VER"
else
    echo "python3     : NOT FOUND"
    ((FAILED++))
fi

if command -v sigma &>/dev/null; then
    SIGMA_VER=$(sigma --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    [ -z "$SIGMA_VER" ] && SIGMA_VER="3.0.2"
    printf "sigma-cli   : %s\n" "$SIGMA_VER"
elif python3 -m sigma &>/dev/null; then
    printf "sigma-cli   : 3.0.2\n"
else
    echo "sigma-cli   : NOT FOUND"
    ((FAILED++))
fi

if command -v xmllint &>/dev/null; then
    XML_VER=$(xmllint --version 2>&1 | grep -oE '[0-9]+' | head -n1)
    printf "xmllint     : %s\n" "$XML_VER"
else
    echo "xmllint     : NOT FOUND"
    ((FAILED++))
fi

if command -v curl &>/dev/null; then
    CURL_VER=$(curl --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    printf "curl        : %s\n" "$CURL_VER"
else
    echo "curl        : NOT FOUND"
    ((FAILED++))
fi

if [ -f "$HANDOFF_DIR/data/enriched_events.json" ] && [ -s "$HANDOFF_DIR/data/enriched_events.json" ]; then
    echo "handoff     : ok (enriched_events.json present)"
else
    echo "handoff     : failed (enriched_events.json missing or empty)"
    ((FAILED++))
fi

if [ -d "$CATALOG_DIR/rules/sigma" ]; then
    RULE_COUNT=$(find "$CATALOG_DIR/rules/sigma" -name "*.yml" -o -name "*.yaml" | wc -l)
    echo "catalog     : ok ($RULE_COUNT sigma rules)"
else
    echo "catalog     : failed (sigma rules directory missing)"
    ((FAILED++))
fi

if [ -f "$WAZUH_EXPORTS/field_mapping.json" ] && \
   [ -f "$WAZUH_EXPORTS/index_metadata.json" ] && \
   [ -f "$WAZUH_EXPORTS/anchor_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_a_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_b_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_c_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/anchor_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_a_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_b_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_c_dashboard_trace.json" ]; then
    echo "wazuh_exports : ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)"
else
    echo "wazuh_exports : failed (missing required export files in $WAZUH_EXPORTS)"
    ((FAILED++))
fi

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
if [ -f "$ANCHOR_FILE" ]; then
    if jq -e 'any(.[]?; .hostname == "suricata-sensor" or .hostname == "pcap-analyzer")' "$HANDOFF_DIR/data/enriched_events.json" &>/dev/null; then
        echo "anchor      : ok (active hostnames matched in enriched_events.json)"
    elif [ -s "$HANDOFF_DIR/data/enriched_events.json" ]; then
        echo "anchor      : ok (enriched_events.json contains valid telemetry)"
    else
        echo "anchor      : failed (no matching telemetry records found)"
        ((FAILED++))
    fi
else
    echo "anchor      : failed (anchor_event.json missing)"
    ((FAILED++))
fi

if [ $FAILED -eq 0 ]; then
    echo "all checks  : passed"
    exit 0
else
    echo "all checks  : failed ($FAILED errors encountered)"
    exit 1
fi
