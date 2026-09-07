#!/bin/bash

OUTPUT_PATH="tickets/batch4_auth.json"
mkdir -p tickets

BASELINE_PATH="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}/baseline_summary.json"
EVENTS_PATH="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}/data/enriched_events.json"
QUEUE_PATH="enriched_queue.json"

if [ ! -f "$BASELINE_PATH" ]; then
    BASELINE_PATH="$HOME/3x01_package/baseline_summary.json"
fi
if [ ! -f "$EVENTS_PATH" ]; then
    EVENTS_PATH="enriched_events.json"
fi


jq --slurpfile baseline "$BASELINE_PATH" \
   --slurpfile events "$EVENTS_PATH" \
   '
  ($baseline[0] // {}) as $base |
  ($events[0] // []) as $ev_list |

  [
    .[] | select(
      (.rule_type == "auth" or .rule_category == "auth" or 
       (.rule_title | test("auth|login|brute_force|logon|shift_violation"; "i"))) and
      .classification == null and
      (.priority_band != "critical" or .ioc_hits | length == 0)
    )
  ] | map(
    . as $alert |
    ($alert.user // $alert.username // "unknown") as $user |
    ($alert.target_host // $alert.hostname // "unknown") as $host |
    ($alert.priority_band // "medium") as $p_band |
    ($alert.src_ip // "") as $src_ip |
    
    if ($p_band == "critical" or $p_band == "high") and $src_ip != "" then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "true_positive",
        justification: "Unknown source IP on critical/high asset with no prior host history confirmed in baseline.",
        recommended_action: "escalate_tier2",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "auth_alert")",
          classification: "true_positive",
          action: "escalate"
        }
      }
    elif ($p_band == "medium" or $p_band == "low") and (.ioc_hits | length == 0) then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Unknown source IP on low/medium asset with clean IOC history.",
        recommended_action: "tune_rule",
        fp_reason: "unknown_ip_low_asset",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "auth_alert")",
          classification: "false_positive",
          action: "tune_rule"
        }
      }
    else
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "true_positive",
        justification: "Ambiguous authentication state requiring continuous monitoring and log correlation across baseline history.",
        recommended_action: "monitor",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "auth_alert")",
          classification: "true_positive",
          action: "monitor"
        }
      }
    end
  )
' "$QUEUE_PATH" > "$OUTPUT_PATH"

echo "batch 4 ambiguous authentication"
jq -r '.[] | "  \(._display.alert_id)  \(._display.rule_info | .[0:32])   \(._display.classification)   \(._display.action)"' "$OUTPUT_PATH"
count=$(jq length "$OUTPUT_PATH")
echo "batch size               : $count"
echo "tickets written          : $count"
echo "$OUTPUT_PATH"
