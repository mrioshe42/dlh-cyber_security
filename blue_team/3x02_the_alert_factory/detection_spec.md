# MedDefense Detection Engineering Specification

## Purpose
This specification defines the operational contract, authoring standards, and quality gates for the MedDefense detection engineering pipeline. It establishes the authoritative standard for transforming raw threat intelligence and telemetry into actionable, prioritized alerts for Tier 1 triage.

## Inputs
- **`$CATALOG_DIR`**: Root directory for rules, configurations, and evaluation outputs (`$HOME/3x02_package/detection_catalog`).
- **`$ASSETS_DIR`**: Location of organizational risk models and asset inventories (`$HOME/3x02_assets`).
- **`$HANDOFF_DIR`**: Source directory for normalized telemetry and baseline datasets (`$HOME/3x00_handoff/evidence_handoff`).
- **Required Files**: `risk_register.json`, `asset_inventory.json`, and normalized event logs.

## Rule Authoring Standard
- **Format**: Valid Sigma YAML specification.
- **Required Fields**: `id` (UUIDv4), `title`, `status`, `level` (`low`, `medium`, `high`, `critical`), `logsource`, and `detection`.
- **Naming Convention**: `NNN_descriptive_name.yml` (e.g., `001_ssh_brute_force.yml`).
- **ATT&CK Tagging**: Every rule must include standard MITRE ATT&CK technique tags using the `attack.tXXXX` or `attack.tXXXX.yyy` format.

## Execution Model
- **Runner**: Executed via `3-sigma_runner.sh` against historical or streaming evaluation windows.
- **Preprocessing Primitives**: Normalization of timestamps to ISO 8601 UTC, IP address sanitization, and canonical labeling.
- **Window Semantics**: Bounded temporal intervals defined by strict start and end ISO timestamps (e.g., `2026-03-25T00:00:00Z,2026-03-25T23:59:59Z`).

## Quality Thresholds
- **Precision**: Minimum acceptable ratio of true positives to total alerts generated.
- **Recall**: Minimum fraction of actual attack instances successfully identified.
- **F1 Score**: Harmonic mean of precision and recall ($F_1 \ge 0.5$ recommended for production deployment).
- **False Positive Rate**: Bounded by volume constraints to prevent Tier 1 alert fatigue.

## Tuning Protocol
- **Identification**: High-noise rules are isolated using precision metrics and false positive volume analysis.
- **Modifier Application**: Refinement via Sigma modifiers, whitelisting known service accounts, or narrowing parent-child process chains.
- **Validation**: Re-running the evaluation window through `3-sigma_runner.sh` to confirm reduced false positives without sacrificing recall.

## Risk Ranking Model
- **Risk Score**: Calculated as the aggregate sum of $(\text{likelihood} \times \text{impact})$ across all risk register scenarios intersecting the rule's MITRE ATT&CK techniques.
- **Priority Score**: Computed as $\text{risk\_score} \times F_1$. Rules with an $F_1$ score of zero are assigned a strict floor score of $\text{risk\_score} \times 0.1$ to flag unvalidated rules.

## Outputs
- **`alert_queue.json`**: Production array of enriched alerts containing deterministic `alert_id` (UUIDv5), `priority_score`, event summaries, asset context, and cryptographic `evidence_hash`.
- **Downstream Contract**: Direct input feed consumed by the 3x03 Triage Shift and Tier 1 operations.

## Failure Modes
1. **Schema Drift**: Downstream consumers fail when `alert_queue.json` keys or types change without schema versioning. Prevented via `alert_queue_schema.json`.
2. **Alert Fatigue**: Noisy rules overwhelm the queue due to missing tuning modifiers, causing critical alerts to be missed. Prevented by strict $F_1$ and false positive gates.
3. **Orphaned Rules**: Rules lacking risk register mappings consume detection engineering bandwidth without business justification. Flagged automatically in the ORPHAN section.

## Reviewer Checklist
- [ ] Sigma rule parses successfully without YAML syntax errors.
- [ ] Unique UUIDv4 assigned to the rule `id` field.
- [ ] Valid MITRE ATT&CK technique tags included (`attack.tXXXX`).
- [ ] Evaluation metrics (`precision`, `recall`, `F1`) verified against baseline.
- [ ] Priority score correctly reflects organizational risk mapping.
