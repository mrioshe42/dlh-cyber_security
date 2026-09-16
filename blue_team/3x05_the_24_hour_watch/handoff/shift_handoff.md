## Shift Identifier
- Shift ID: SHIFT-20260915-01
- Analyst Host: soc-analyst-01
- Started At: 2026-09-16T00:00:00Z
- Ended At: 2026-09-15T22:01:13.901009+00:00
- Duration: 22.02 hours

## Situation
During this operational shift, heightened telemetry monitoring was active in response to the HC-RED7 threat advisory. A
 total of 3 primary incidents were correlated and investigated across clinical and administrative zones. Threat intelli
gence feeds confirmed active indicator matches and coordinated adversary behavior targeting core hospital services. All
 anomalies were thoroughly triaged and categorized to secure the environment.

## Incidents
- Incident INC-20260915-A: Classified as a True Positive (TP). Evidence confirmed active credential abuse followed by u
nauthorized service installation and C2 beaconing. Detailed findings are documented in reports/incident_A.md.
- Incident INC-20260915-B: Classified as True Positive (TP) after resolving initial ambiguity. While superficial mainte
nance change windows matched, execution by an unauthorized account and outbound IOC traffic confirmed malicious activit
y. Documented in reports/incident_B.md.
- Incident INC-20260915-C: Classified as True Positive (TP). Lateral movement and privilege escalation patterns linked 
directly to the primary intrusion vector. Documented in reports/incident_C.md.

## Campaign Assessment
The incidents are definitively campaign-linked under cluster ID HC-RED7 with high confidence, as validated in campaign/
campaign_assessment.json. Shared tactical overlaps, temporal proximity, and direct feed IOC matches confirm a unified i
ntrusion campaign.

## Open Items for Next Shift
1. Monitor firewall blocks for perimeter telemetry on IP 198[.]51[.]100[.]73 using Suricata logs.
2. Verify completion of credential rotations for affected administrative accounts.
3. Review endpoint agent logs on rad-srv-02 to ensure no secondary persistence artifacts remain.
4. Validate backup integrity on infrastructure nodes following incident containment.

## Artifact Index
| Path | SHA-256 (Prefix) |
| --- | --- |
| `0-shift_intake.sh` | `e3768bfc617b5273...` |
| `1-run_pipeline.sh` | `0d83242531994666...` |
| `10-campaign_correlation.sh` | `ce86362f2cd7fa94...` |
| `11-incident_reports.sh` | `226e70bb043fa128...` |
| `13-containment_package.sh` | `93a50a61cd921b00...` |
| `14-shift_handoff.sh` | `d3c3e68f54478a5d...` |
| `2-run_baselines.sh` | `a47dd08c002da4fd...` |
| `3-run_detections.sh` | `2ea7f4472e3f46c2...` |
| `4-shift_briefing.sh` | `0b1a5b69254f15e9...` |
| `5-triage_queue.sh` | `27a829f4cca3c59f...` |
| `6-correlate_alerts.sh` | `7f131827996ef76c...` |
| `7-investigate_a.sh` | `5f261957df51f034...` |
| `8-investigate_B.sh` | `4de1dd77bf6d9668...` |
| `alerts/alert_queue.json` | `b7cd7145bf765477...` |
| `alerts/incidents.json` | `caa0d3be10baf15b...` |
| `alerts/shift_briefing.json` | `20c09847932b5151...` |
| `alerts/triage_log.jsonl` | `8ea982965c69348b...` |
| `campaign/campaign_assessment.json` | `9012512516bb7c9b...` |
| `enriched/baseline.json` | `875dd7bafd0479ab...` |
| `enriched/enriched_events.jsonl` | `a48acc19c00aa38e...` |
| `enriched/source_stats.json` | `27d0fa91d8afc8f7...` |
| `enriched/timeline.jsonl` | `e1949ce2105021f2...` |
| `investigations/incident_A.json` | `23e2935cf85a5445...` |
| `investigations/incident_B.json` | `debf5fd5d1b3d80b...` |
| `investigations/incident_C_cli.json` | `84ebc8c334be1eae...` |
| `investigations/incident_C_export.json` | `a5ec58b010437fe2...` |
| `reports/incident_A.md` | `70080cd5f484a29c...` |
| `reports/incident_B.md` | `d202f93c8ecbb7a6...` |
| `reports/incident_C.md` | `d7469de0ad7f1e8e...` |
| `response/containment.json` | `ff9f5efea99e4b7b...` |
| `response/ioc_package.json` | `99c4951e595b5c10...` |
| `response/tuning_recommendations.json` | `ec1f22a23d163b60...` |
| `runtime/baseline_run.json` | `78a844a444b60e87...` |
| `runtime/catalog_run.json` | `d06cf7327f46e286...` |
| `runtime/pipeline_run.json` | `a4c40a713d67c4f1...` |
| `runtime/pipeline_run.log` | `fea1610e581f7260...` |
| `runtime/shift_start.json` | `51537fa4af61b98b...` |
