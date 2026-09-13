# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose
This playbook establishes a standardized, platform-independent investigation workflow for Tier 1 SOC analyst
s at MedDefense Health Systems. It provides dual-path methodologies for CLI pipelines and SIEM dashboard exp
orts to ensure consistent, verifiable incident triage.

## Scope
Covers SIEM investigations, forensic event correlation, behavioral anomaly identification, and threat huntin
g across clinical and corporate assets. It excludes physical security incidents and direct live-system conta
inment actions.

## Inputs
1. Enriched event evidence packs (`enriched_events.json`, `network_events.json`)
2. Asset inventory (`asset_inventory.json`)
3. System and network baselines (`baseline_package`)
4. Detection catalog (`detection_catalog/rules/sigma/`)
5. Triage package & IOC context (`triage_package`, `ioc_context.json`)
6. Wazuh field mappings and index metadata (`wazuh_exports/`)

## Workflow Steps

| Step | CLI Action | Export / Dashboard Action |
| :--- | :--- | :--- |
| **1. Init** | Verify environment variables and tool binaries (`jq`, `yq`, `sigma`). | Confirm export artif
act integrity and load `index_metadata.json`. |
| **2. Ingestion** | Read scenario manifest (`scenario_*.json`) for parameters. | Load pre-generated search 
results and query metadata. |
| **3. Filtering** | Apply `jq` time-window and host filters to raw evidence. | Execute KQL filters in Disco
ver view or review search export JSON. |
| **4. Normalization** | Map flat-file fields directly via custom script logic. | Reconcile fields using `fi
eld_mapping.json` (e.g., `hostname` to `agent.name`). |
| **5. Chain Reconstruction** | Join multi-event sequences (EID 10 -> 11 -> 3) chronologically. | Expand mat
ching document flyouts to trace attack progression. |
| **6. Context Join** | Merge asset criticality and zone rules via inventory lookup. | Review agent labels a
nd zone tags within document metadata. |
| **7. Validation** | Formulate hypothesis, map ATT&CK techniques, score confidence. | Compare findings agai
nst dashboard summary trace notes. |
| **8. Reporting** | Write structured finding conforming to locked JSON schema. | Export finding record and 
log time-to-first-answer metrics. |

## Field Name Translation Table

| Normalized Schema | Wazuh / Elastic Field Name |
| :--- | :--- |
| `hostname` | `agent.name` |
| `src_ip` | `source.ip` |
| `dst_ip` | `destination.ip` |
| `user` | `user.name` |
| `event_id` | `winlog.event_id` |
| `raw_message` | `full_log` |
| `event_ref` | `_id` |
| `process_name` | `process.name` |
| `command_line` | `process.command_line` |
| `bytes_out` | `network.bytes` |

## Query Decomposition Rule
Every investigation query decomposes into three components: **Filter** (target host/IP), **Aggregation** (ev
ent categories/IDs), and **Time Window** (strict ISO-8601 bounds).
- **CLI (`jq`)**: `jq -c 'select(.timestamp >= "START" and .timestamp <= "END") | select(.hostname == "HOST"
)'`
- **Sigma**: `logsource` specification paired with `detection` selection blocks.
- **KQL**: `agent.name:"HOST" AND winlog.event_id:(EID_LIST)`
- **Lucene**: `timestamp:[START TO END] AND agent.name:HOST`

## Finding Schema
All findings must conform to the locked schema containing: `finding_id`, `scenario_id`, `interface`, `invest
igation_start`, `investigation_end`, `time_to_first_answer_seconds`, `actions`, `fields_touched`, `event_ref
s`, `attack_techniques`, `hypothesis`, `confidence`, and `created_at`.

## Exit Criteria
An investigation is complete when all scenario indicators are verified against telemetry, timeline bounds ar
e established, ATT&CK techniques are mapped, and a validated JSON finding is written to disk.

## Known Pitfalls
1. Assuming flat-file field names exist unmodified in Wazuh exports without applying `field_mapping.json`.
2. Omitting asset criticality and data classification context when evaluating off-hours privileged access.
3. Failing to normalize timestamp bounds between UTC event logs and local sensor collection intervals.
