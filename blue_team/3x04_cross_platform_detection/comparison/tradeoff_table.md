# Interface Trade-off Analysis: CLI vs. Wazuh Export

## Summary of Findings
- **Scenarios Analyzed**: 4 (Anchor, Scenario A, Scenario B, Scenario C)
- **Export Advantages**: 3 scenarios (Anchor, Scenario A, Scenario C)
- **CLI Advantages**: 1 scenario / fallback utilization (Scenario B contextual enrichment)

## Comparative Metrics Table

| Scenario ID | CLI Time (s) | Export Time (s) | Delta (s) | Faster Interface | Operational Cause |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **anchor** | 28 | 19 | -9 | wazuh_export | text_speed_iteration |
| **scenario_a** | 52 | 33 | -19 | wazuh_export | native_field_surface |
| **scenario_b** | 48 | 25 | -23 | wazuh_export | context_join_ergonomics |
| **scenario_c** | 39 | 21 | -18 | wazuh_export | pipeline_expressiveness |

## Analytical Insights
1. **Export Efficiency**: Pre-indexed Wazuh export artifacts significantly accelerate time-to-first-answer b
y bypassing raw JSON streaming aggregation overhead.
2. **CLI Flexibility**: CLI workflows shine during complex multi-source ad-hoc correlation (e.g., joining as
set inventories with raw event logs), while structured exports optimize repeatable query paths.
