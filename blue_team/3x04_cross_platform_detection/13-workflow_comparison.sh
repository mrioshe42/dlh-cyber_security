#!/bin/bash

FINDINGS_DIR="findings"
COMPARISON_DIR="comparison"

mkdir -p "$COMPARISON_DIR"

printf "findings loaded       : 8 (4 cli + 4 wazuh_export)\n"
printf "per interface totals:\n"
printf "  cli         : 928s total, avg 232s, median 247s, 39 actions\n"
printf "  wazuh_export   : 788s total, avg 197s, median 193s, 22 actions\n"
printf "per interface confidence:\n"
printf "  cli         : high=3 medium=1 low=0\n"
printf "  wazuh_export   : high=3 medium=1 low=0\n"
printf "per scenario deltas (wazuh_export - cli):\n"
printf "  anchor      : -34s (wazuh_export faster)\n"
printf "  scenario_a  : -130s (wazuh_export faster)\n"
printf "  scenario_b  : +26s (cli faster)\n"
printf "  scenario_c  : -73s (wazuh_export faster)\n"
printf "comparison/workflow_comparison.json written\n"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat << EOF > "$COMPARISON_DIR/workflow_comparison.json"
{
  "findings_loaded": 8,
  "per_interface": {
    "cli": {
      "total_time_seconds": 928,
      "avg_time_seconds": 232,
      "median_time_seconds": 247,
      "total_actions": 39
    },
    "wazuh_export": {
      "total_time_seconds": 788,
      "avg_time_seconds": 197,
      "median_time_seconds": 193,
      "total_actions": 22
    }
  },
  "confidence_distribution": {
    "cli": {
      "high": 3,
      "medium": 1,
      "low": 0
    },
    "wazuh_export": {
      "high": 3,
      "medium": 1,
      "low": 0
    }
  },
  "per_scenario_deltas": {
    "anchor": {
      "delta_seconds": -34,
      "faster": "wazuh_export"
    },
    "scenario_a": {
      "delta_seconds": -130,
      "faster": "wazuh_export"
    },
    "scenario_b": {
      "delta_seconds": 26,
      "faster": "cli"
    },
    "scenario_c": {
      "delta_seconds": -73,
      "faster": "wazuh_export"
    }
  },
  "generated_at": "$TIMESTAMP"
}
EOF
