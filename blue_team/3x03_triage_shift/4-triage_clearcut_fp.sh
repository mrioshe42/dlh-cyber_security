#!/bin/bash

OUTPUT_PATH="tickets/batch2_clearcut_fp.json"
mkdir -p tickets

jq -c '
  [
    .[] | select(
      (.alert_id == "alert_00003" or .alert_id == "alert_00025") or
      (.alert_id == "alert_00008" or .alert_id == "alert_00034") or
      (.alert_id == "alert_00011" or .alert_id == "alert_00029")
    )
  ] | sort_by(.alert_id) | map(
    if .alert_id == "alert_00003" or .alert_id == "alert_00025" then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Alert triggered by authorized service account activity matching authentication or process baseline patterns.",
        recommended_action: "tune_rule",
        fp_reason: "service_account_activity",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "002 windows_offhours_priv_logon",
          action: "CLOSE",
          fp_reason: "service_account_activity"
        }
      }
    elif .alert_id == "alert_00008" or .alert_id == "alert_00034" then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Alert triggered from management subnet range during authorized administrative network traffic.",
        recommended_action: "tune_rule",
        fp_reason: "management_subnet",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "007 unknown_outbound_destination",
          action: "CLOSE",
          fp_reason: "management_subnet"
        }
      }
    else
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Alert matched a known process name present in the baseline host profile expected execution list.",
        recommended_action: "tune_rule",
        fp_reason: "baseline_match",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: (if .alert_id == "alert_00011" then "003 interpreter_abuse" else "004 recon_tool_execution" end),
          action: "CLOSE",
          fp_reason: "baseline_match"
        }
      }
    end
  )
' enriched_queue.json > "$OUTPUT_PATH"

echo "batch 2 clear-cut false positives"
jq -r '.[] | "  \(._display.alert_id)  \(._display.rule_info) \(_display.action)  \(._display.fp_reason)"' "$OUTPUT_PATH"
count=$(jq length "$OUTPUT_PATH")
echo "batch size               : $count"
echo "tickets written          : $count"
echo "$OUTPUT_PATH"
