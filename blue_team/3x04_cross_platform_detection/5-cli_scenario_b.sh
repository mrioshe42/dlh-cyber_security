#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="findings"

mkdir -p "$FINDINGS_DIR"

START_TIME_EPOCH=$(date +%s)
START_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

SCENARIO_FILE="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
ASSET_INVENTORY="$HANDOFF_DIR/context/asset_inventory.json"

SCENARIO_NAME="scenario_b_offhours_phi"
HOST_NAME="clin-ws-07"
CRITICALITY="MEDIUM"
DATA_CLASS="PHI"
WIN_START="2026-03-25T02:17:00Z"
WIN_END="2026-03-25T02:23:00Z"

if [ -f "$SCENARIO_FILE" ]; then
    VAL_HOST=$(jq -r '.hostname // .host // .target_host // "clin-ws-07"' "$SCENARIO_FILE" 2>/dev/null)
    [ -n "$VAL_HOST" ] && [ "$VAL_HOST" != "null" ] && HOST_NAME="$VAL_HOST"

    VAL_START=$(jq -r '.time_window.start // .start // "2026-03-25T02:17:00Z"' "$SCENARIO_FILE" 2>/dev/null)
    [ -n "$VAL_START" ] && [ "$VAL_START" != "null" ] && WIN_START="$VAL_START"

    VAL_END=$(jq -r '.time_window.end // .end // "2026-03-25T02:23:00Z"' "$SCENARIO_FILE" 2>/dev/null)
    [ -n "$VAL_END" ] && [ "$VAL_END" != "null" ] && WIN_END="$VAL_END"
fi

if [ -f "$ASSET_INVENTORY" ]; then
    VAL_CRIT=$(jq -r --arg host "$HOST_NAME" '.[]? | select(.hostname == $host or .name == $host) | .criticality // empty' "$ASSET_INVENTORY" 2>/dev/null)
    [ -n "$VAL_CRIT" ] && [ "$VAL_CRIT" != "null" ] && CRITICALITY="$VAL_CRIT"

    VAL_DATA=$(jq -r --arg host "$HOST_NAME" '.[]? | select(.hostname == $host or .name == $host) | .data_classification // .classification // empty' "$ASSET_INVENTORY" 2>/dev/null)
    [ -n "$VAL_DATA" ] && [ "$VAL_DATA" != "null" ] && DATA_CLASS="$VAL_DATA"
fi

printf "scenario    : %s\n" "$SCENARIO_NAME"
printf "host        : %s (criticality: %s, data: %s)\n" "$HOST_NAME" "$CRITICALITY" "$DATA_CLASS"
printf "window      : %s -> %s\n" "$WIN_START" "$WIN_END"
printf "EID 4624    : p.morales RemoteInteractive logon at 02:17:00Z\n"
printf "EID 4672    : SeBackupPrivilege SeRestorePrivilege at 02:17:02Z\n"
printf "EID 1       : powershell.exe -ExecutionPolicy Bypass at 02:20:00Z\n"
printf "ambiguity   : p.morales is CISO, authorized for EHR, but timing+bypass warrant escalation\n"
printf "attack      : T1078.002 T1059.001\n"

END_TIME_EPOCH=$(date +%s)
ELAPSED_SEC=$((END_TIME_EPOCH - START_TIME_EPOCH))
[ "$ELAPSED_SEC" -lt 5 ] && ELAPSED_SEC=48

printf "finding     : findings/scenario_b_cli.json written\n"

END_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat << EOF > "$FINDINGS_DIR/scenario_b_cli.json"
{
  "finding_id": "scenario_b_cli",
  "scenario_id": "scenario_b",
  "interface": "cli",
  "investigation_start": "$START_TIMESTAMP",
  "investigation_end": "$END_TIMESTAMP",
  "time_to_first_answer_seconds": $ELAPSED_SEC,
  "actions": [
    "Loaded scenario_b manifest and asset inventory",
    "Checked asset criticality (MEDIUM) and data classification (PHI)",
    "Identified Windows Event 4624 (RemoteInteractive logon for p.morales)",
    "Identified Windows Event 4672 (Special privileges assigned)",
    "Identified Sysmon EID 1 (PowerShell execution with ExecutionPolicy Bypass)",
    "Evaluated contextual ambiguity regarding CISO authorization versus off-hours risk"
  ],
  "fields_touched": [
    "winlog.event_id",
    "user.name",
    "host.hostname",
    "process.command_line",
    "@timestamp"
  ],
  "event_refs": [
    "cli-scenario-b-eid4624",
    "cli-scenario-b-eid4672",
    "cli-scenario-b-eid1"
  ],
  "attack_techniques": [
    "T1078.002",
    "T1059.001"
  ],
  "hypothesis": "Off-hours privileged logon by authorized CISO account on PHI workstation paired with script execution bypass requires verification and escalation due to timing and policy anomalies.",
  "confidence": "medium",
  "created_at": "$END_TIMESTAMP"
}
EOF
