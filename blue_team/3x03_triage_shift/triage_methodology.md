# MedDefense SOC Triage Methodology

## Classification Taxonomy
- **true_positive**: An alert representing verified malicious activity requiring immediate containment, such as rule `010` (credential_theft_chain) firing on unauthorized credential dumping behavior.
- **false_positive**: An alert triggered by benign operational activity incorrectly flagged by a detection rule, such as rule `001` (ssh_brute_force) firing on a legitimate automated administrative script.
- **benign**: An alert caused by expected, low-risk internal activity that requires no further action or rule modification, such as rule `012` (medical_segment_egress) firing on routine hospital backup data egress.
- **escalated**: A true positive that meets severity thresholds and has been packaged with complete context for Tier 2 handoff, such as rule `011` (patient_data_access) capturing active unauthorized record exfiltration.

## Priority Ordering Rule
Analysts process the queue strictly descending by `priority_score`, overriding queue order only when a host flagged as critical in `asset_inventory.json` triggers a cluster of correlated medium-priority alerts within a 10-minute window.

## Evidence Requirement
Every non-benign classification must reference at least one explicit event pointer (`event_ref`) from `enriched_events.json`, naming specific fields such as `src_ip`, `dest_ip`, or `user` that substantiate the operational verdict.

## Escalation Criteria
- `priority_score >= 20` combined with a malicious reputation tag present in `ioc_context.json`.
- Active lateral movement verified via anomalous internal connection chains across sensitive network zones.
- Confirmed unauthorized access attempts targeting core patient database assets.

## SLA
- **critical**: 15 minutes maximum response and triage time.
- **high**: 30 minutes maximum response and triage time.
- **medium**: 60 minutes maximum response and triage time.
- **low**: Processed same business shift.

## Documentation Standard
- `ticket_id`: Deterministic unique identifier derived from the source alert ID.
- `alert_id`: Original identifier from `alert_queue.json`.
- `classification`: Taxonomic classification (`true_positive`, `false_positive`, `benign`, `escalated`).
- `justification`: Explicit plain-text rationale citing specific field values.
- `evidence_refs`: Array of pointers referencing `enriched_events.json`.
- `ioc_hits`: Array of matching indicators from `ioc_context.json`.
- `attack_techniques`: Array of MITRE ATT&CK technique IDs from the source rule.
- `recommended_action`: Operational directive (`close`, `escalate_tier2`, `monitor`, `tune_rule`).
- `analyst_time_seconds`: Processing duration from alert open to classification.
- `created_at`: ISO 8601 UTC timestamp.