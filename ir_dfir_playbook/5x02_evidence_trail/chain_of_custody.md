# Chain of Custody: `<case_number>`

## Case Header

- **Case number:** `<case_number>`
- **Incident ID:** `<incident_id>`
- **Lead investigator:** `<investigator_name>`
- **Date opened:** `<YYYY-MM-DD>`
- **Litigation hold reference:** `<legal_memo_reference>`

## Artifact Registry

| Artifact ID | Artifact Name | Format | Acquired By | Acquisition Timestamp (UTC) | Acquisition Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ART-001 | `<disk_image_filename>` | RAW/dd | `<network_engineer_name>` | `<YYYY-MM-DDTHH:MMZ>` | Disk imaging tool | Not computed at acquisition | Evidence storage location; exact path unverified | Not documented; read-only access required |
| ART-002 | `<memory_dump_filename_1>` | RAW memory | `<network_engineer_name>` | `<YYYY-MM-DDTHH:MMZ>` | Memory acquisition tool | Not computed at acquisition | Evidence storage location; exact path unverified | Not documented; read-only access required |
| ART-003 | `<memory_dump_filename_2>` | RAW memory | `<network_engineer_name>` | `<YYYY-MM-DDTHH:MMZ>` | Memory acquisition tool | Not computed at acquisition | Evidence storage location; exact path unverified | Not documented; read-only access required |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified (yes/no) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `<YYYY-MM-DDTHH:MMZ>` | Monitoring system | ART-001 (source), ART-002 (source), ART-003 (source) | alert_detection | Detection engine | no | Initial incident trigger. Alert identification recorded. Scope limited at detection time. |
| `<YYYY-MM-DDTHH:MMZ>` | `<engineer_name>` | ART-002 | acquire_memory | Memory acquisition tool | no | Volatile memory capture from live source system. Transfer method documented. |
| `<YYYY-MM-DDTHH:MMZ>` | `<ir_commander>` | ART-001 (source) | isolation_decision | Incident response playbook | no | Network isolation strategy authorized. Remote forensic access pathway established. |
| `<YYYY-MM-DDTHH:MMZ>` | `<analyst_name>` | ART-001 (source) | remote_forensic_access | Remote access tool | no | Live-system forensic access established. Volatile data collection initiated before disk acquisition. |
| `<YYYY-MM-DDTHH:MMZ>` | `<engineer_name>` | ART-003 | acquire_memory | Memory acquisition tool | no | Scope expansion: secondary host memory captured. Same acquisition method as primary. Transfer method documented. |
| `<YYYY-MM-DDTHH:MMZ>` | IR operations team | ART-001, ART-002, ART-003 | evidence_preservation_notice | Evidence preservation playbook | no | Formal evidence preservation notice issued. All artifacts flagged for custody tracking. Litigation hold pending. |
| `<YYYY-MM-DDTHH:MMZ>`, exact time not recorded | `<engineer_name>` | ART-001 (source) | read_write_mount | File system explorer | no | Pre-imaging artifact location verification. Source filesystem mounted with write access. File system metadata access possible. |
| `<YYYY-MM-DDTHH:MMZ>` | `<engineer_name>` | ART-001 | acquire_disk_start | Disk imaging tool | no | Disk acquisition initiated on isolated host. Source filesystem not in read-only mode during acquisition. |
| `<YYYY-MM-DDTHH:MMZ>` | `<engineer_name>` | ART-001 | acquire_disk_complete | Disk imaging tool | no | Disk image acquisition completed. Raw/dd format. Acquisition duration documented. Transfer method recorded. |
| `<YYYY-MM-DDTHH:MMZ>` | Legal counsel | ART-001, ART-002, ART-003 | litigation_hold | Legal notice | no | Litigation hold placed on all artifacts. Evidence retention and integrity preservation mandatory. |
| `<YYYY-MM-DDTHH:MMZ>` | `<engineer_name>` | ART-001, ART-002, ART-003 | acquisition_handoff | Acquisition documentation | no | Artifacts transferred to evidence storage. Acquisition notes document gaps: no acquisition hashes, no contemporaneous CoC form, filesystem access before imaging, transfer path verification unavailable. |
| `<YYYY-MM-DDTHH:MMZ>` | System administration | ART-001 (source) | source_system_rebuild | Clean system image | no | Source host rebuilt from baseline image. Original source no longer available. Artifact capture final and unreproducible. |
| `<YYYY-MM-DDTHH:MMZ>` | System administration | ART-003 (source) | source_system_rebuild | Clean system image | no | Secondary source host rebuilt from baseline image. Original source no longer available. Artifact capture final and unreproducible. |

## Evidence Integrity and Handling Rules

- Litigation hold applies to all artifacts from date of legal notice.
- Preserve original evidence without modification or deletion.
- Establish SHA-256 baseline hashes before first forensic analysis access.
- Acquisition hashes are unavailable and must not be reconstructed or invented.
- Perform forensic analysis on verified working copies only.
- Append every subsequent access to this log with timestamp, actor, artifact, action, tool, hash verification, and notes.
- Record any hash mismatch immediately as DEVIATION.
- Source systems have been rebuilt and are not available for verification or re-acquisition.

## Known Evidence Gaps

- No SHA-256 hashes were recorded at acquisition time.
- No contemporaneous chain-of-custody form was completed at acquisition.
- Physical and network access to artifacts between acquisition and evidence storage was not documented.
- Source filesystem was mounted with write access before disk imaging; file system metadata may have been modified.
- Volatile memory artifacts were transferred via external storage device; transfer path integrity cannot be independently verified.
- Forensic access to live source system occurred before disk acquisition was complete, creating temporal overlap between live analysis and disk imaging.
- Disk acquisition was not performed under read-only conditions; source filesystem remained writable during imaging.
- Exact evidence storage paths and access control enforcement remain unverified.
- Source systems have been rebuilt and are not available for re-acquisition or reverification.
- Baseline SHA-256 hashes remain pending until artifacts are available to analyst.
