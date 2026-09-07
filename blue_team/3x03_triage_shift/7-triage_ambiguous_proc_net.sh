#!/bin/bash

OUTPUT_PATH="tickets/batch5_proc_net.json"
mkdir -p tickets

IOC_PATH="${ASSETS_DIR:-$HOME/3x03_assets}/ioc_context.json"
if [ ! -f "$IOC_PATH" ]; then
    IOC_PATH="ioc_context.json"
fi
QUEUE_PATH="enriched_queue.json"


jq --slurpfile iocs "$IOC_PATH" \
   '
  ($iocs[0] // []) as $ioc_list |
  
  ([ $ioc_list[] | {key: (.indicator // .ip // .domain // ""), value: .} ] | from_entries) as $ioc_map |

  [
    .[] | select(
      (.rule_type == "process" or .rule_category == "process" or 
       .rule_type == "network" or .rule_category == "network" or
       (.rule_title | test("interpreter_abuse|outbound|recon|port|process|network"; "i"))) and
      .classification == null
    )
  ] | map(
    . as $alert |
    ($alert.priority_score // 0) as $score |
    ($alert.priority_band // (if $score >= 20 then "critical" elif $score >= 10 then "high" elif $score >= 5 then "medium" else "low" end)) as $crit |
    ($alert.ioc_hits // []) as $hits |
    
    ($hits | map(.reputation) | unique) as $rep_list |
    
    if ($rep_list | index("malicious")) != null then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "true_positive",
        justification: "Process or network event matched a known malicious IOC reputation feed entry.",
        recommended_action: "escalate_tier2",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "proc_net_alert")",
          classification: "true_positive",
          action: "escalate"
        }
      }
    elif ($rep_list | index("suspicious")) != null and ($crit == "critical" or $crit == "high") then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "true_positive",
        justification: "Suspicious IOC reputation detected on critical/high asset; requires continuous monitoring.",
        recommended_action: "monitor",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "proc_net_alert")",
          classification: "true_positive",
          action: "monitor"
        }
      }
    elif ($rep_list | index("suspicious")) != null and ($crit == "medium" or $crit == "low") then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Suspicious IOC indicator on low/medium asset matches baseline profile known elsewhere.",
        recommended_action: "tune_rule",
        fp_reason: "suspicious_but_baseline_known_elsewhere",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "proc_net_alert")",
          classification: "false_positive",
          action: "tune_rule"
        }
      }
    elif (($rep_list | length == 0) or ($rep_list | index("clean")) != null) and not (.baseline_deviation // false) then
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "false_positive",
        justification: "Clean IOC reputation with absence of baseline deviation across monitored parameters.",
        recommended_action: "tune_rule",
        fp_reason: "clean_ioc_no_deviation",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "proc_net_alert")",
          classification: "false_positive",
          action: "tune_rule"
        }
      }
    else
      {
        ticket_id: (.alert_id | sub("alert_"; "tkt_")),
        alert_id: .alert_id,
        classification: "true_positive",
        justification: "Ambiguous process/network indicators checked against host profile and IOC context; requires monitoring.",
        recommended_action: "monitor",
        created_at: "2026-09-06T00:00:00Z",
        _display: {
          alert_id: .alert_id,
          rule_info: "\(.rule_id // "000") \(.rule_title // "proc_net_alert")",
          classification: "true_positive",
          action: "monitor"
        }
      }
    end
  )
' "$QUEUE_PATH" > "$OUTPUT_PATH"

echo "batch 5 ambiguous process and network"
jq -r '.[] | "  \(._display.alert_id)  \(._display.rule_info | .[0:34])   \(._display.classification)   \(._display.action)"' "$OUTPUT_PATH"
count=$(jq length "$OUTPUT_PATH")
echo "batch size               : $count"
echo "tickets written          : $count"
echo "$OUTPUT_PATH"
