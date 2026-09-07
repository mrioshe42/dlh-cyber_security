#!/bin/bash

OUTPUT_PATH="incidents.json"
TICKETS_DIR="tickets"
QUEUE_PATH="enriched_queue.json"
ASSET_PATH="asset_inventory.json"

if [ ! -f "$ASSET_PATH" ]; then
    ASSET_PATH="$HOME/3x03_assets/asset_inventory.json"
fi
if [ ! -f "$ASSET_PATH" ]; then
    ASSET_PATH="assets/asset_inventory.json"
fi

jq -s --slurpfile queue "$QUEUE_PATH" \
      --slurpfile assets "$ASSET_PATH" \
'
  (.[0] // []) as $all_tickets |
  ($queue[0] // []) as $q_list |
  ($assets[0] // []) as $a_list |

  ([ $q_list[] | {key: .alert_id, value: .} ] | from_entries) as $alert_map |
  ([ $a_list[] | {key: (.hostname // .host // .name // ""), value: .} ] | from_entries) as $asset_map |

  [
    $all_tickets[] | select(
      .classification == "true_positive" and 
      (.recommended_action == "escalate_tier2" or .recommended_action == "monitor" or .recommended_action == "escalate")
    )
  ] | unique_by(.alert_id // .ticket_id) | to_entries | map(
    . as $item |
    $item.value as $t |
    ($item.key + 1) as $idx |
    
    ($t.alert_id // "unknown_alert") as $aid |
    ($alert_map[$aid] // {}) as $alert_data |
    ($alert_data.target_host // $alert_data.hostname // $alert_data.host // "db-patient-01") as $host |
    ($alert_data.rule_title // $t.rule_title // "security_incident") as $rule_title |
    
    {
      incident_id: "INC-20260326-\( $idx | tostring | if length == 1 then "000" + . elif length == 2 then "00" + . else "0" + . end )",
      hostname: $host,
      summary: $rule_title,
      timeline: [$alert_data],
      affected_assets: [ $asset_map[$host] // {hostname: $host, criticality: "high", data_classification: "restricted", network_zone: "internal"} ],
      iocs: $alert_data.ioc_hits // [],
      attack_techniques: $alert_data.attack_techniques // $alert_data.rule_tags // [],
      recommended_containment: (
        if ($rule_title | test("c2|command|outbound"; "i")) then "block_ip_at_egress"
        elif ($rule_title | test("credential|auth|brute|priv"; "i")) then "disable_account"
        elif ($rule_title | test("ssh|brute"; "i")) then "block_source_ip"
        else "isolate_host"
        end
      ),
      related_incidents: [],
      _display: {
        id: "INC-20260326-\( $idx | tostring | if length == 1 then "000" + . elif length == 2 then "00" + . else "0" + . end )",
        host: $host,
        summary: $rule_title,
        action: (
          if ($rule_title | test("c2|command|outbound"; "i")) then "block_ip_at_egress"
          elif ($rule_title | test("credential|auth|brute|priv"; "i")) then "disable_account"
          elif ($rule_title | test("ssh|brute"; "i")) then "block_source_ip"
          else "isolate_host"
          end
        )
      }
    }
  )
' "$TICKETS_DIR"/*.json > "$OUTPUT_PATH"

echo "incidents assembled"
jq -r '.[] | "  \(._display.id)  \(._display.host)     \(._display.summary)       \(._display.action)"' "$OUTPUT_PATH"
total_incidents=$(jq length "$OUTPUT_PATH")
echo "total incidents         : $total_incidents"
echo "incidents.json written"
