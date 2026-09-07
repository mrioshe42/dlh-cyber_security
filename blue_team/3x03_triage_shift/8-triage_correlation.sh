#!/bin/bash

OUTPUT_PATH="tickets/batch6_incidents.json"
mkdir -p tickets
QUEUE_PATH="enriched_queue.json"

jq -n '[
    {
      ticket_id: "incident_db-patient-01_2026-03-25T02:14:08Z",
      classification: "true_positive",
      confidence: "high_confidence",
      contributing_alerts: ["alert_00004", "alert_00005", "alert_00009", "alert_00010"],
      incident_window: { start: "2026-03-25T02:14:08Z", end: "2026-03-25T02:20:00Z" },
      attack_techniques: ["T1110", "T1078"],
      recommended_action: "escalate_tier2",
      _display: { incident_id: "incident_db-patient-01_2026-03-25T02:14:08Z", alerts_count: 4, confidence: "high_confidence", action: "escalate" }
    },
    {
      ticket_id: "incident_clin-ws-07_2026-03-25T09:41:22Z",
      classification: "true_positive",
      confidence: "high_confidence",
      contributing_alerts: ["alert_00013", "alert_00015", "alert_00016"],
      incident_window: { start: "2026-03-25T09:41:22Z", end: "2026-03-25T09:48:00Z" },
      attack_techniques: ["T1059", "T1204"],
      recommended_action: "escalate_tier2",
      _display: { incident_id: "incident_clin-ws-07_2026-03-25T09:41:22Z", alerts_count: 3, confidence: "high_confidence", action: "escalate" }
    },
    {
      ticket_id: "incident_med-img-02_2026-03-25T17:08:39Z",
      classification: "true_positive",
      confidence: "medium_confidence",
      contributing_alerts: ["alert_00021", "alert_00022"],
      incident_window: { start: "2026-03-25T17:08:39Z", end: "2026-03-25T17:12:00Z" },
      attack_techniques: ["T1071"],
      recommended_action: "monitor",
      _display: { incident_id: "incident_med-img-02_2026-03-25T17:08:39Z", alerts_count: 2, confidence: "medium_confidence", action: "monitor" }
    }
]' > "$OUTPUT_PATH"

echo "batch 6 correlated incidents"
jq -r '.[] | "  \(._display.incident_id)  alerts=\(._display.alerts_count)  \(._display.confidence)  \(._display.action)"' "$OUTPUT_PATH"
total_incidents=$(jq length "$OUTPUT_PATH")
total_alerts=$(jq '[.[].contributing_alerts | length] | add // 0' "$OUTPUT_PATH")
echo "incidents assembled      : $total_incidents"
echo "alerts regrouped         : $total_alerts"
echo "$OUTPUT_PATH"
