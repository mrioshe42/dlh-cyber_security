# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-10-31 | **Basis:** Nexus/Cobalt Strike incident (2026-03-25) + remediation plan

## Gap Assessment Matrix

| CSF | Subcategory | Title | Status | Evidence | Severity | Gap |
|---|---|---|---|---|---|---|
| GOVERN | GV.OC-01 | Risk strategy | Partial | risk_register_updates.yaml | High | Risk register exists; no board-approved charter |
| GOVERN | GV.PO-01 | Policies | Not Impl. | None | **Critical** | Missing AUP, Data Classification, Vendor policies |
| GOVERN | GV.SC-04 | Vendor inventory | Not Impl. | None | High | No vendor tiering; Nexus, CloudVault unmanaged |
| GOVERN | GV.SC-07 | Vendor risk | Not Impl. | None | High | Supply chain risk not formalized in register |
| IDENTIFY | ID.AM-01 | Asset inventory | Partial | endpoint_hardening_baseline.md | Medium | Workstations 280/3 done; medical devices absent |
| IDENTIFY | ID.RA-01 | Vulnerabilities | **Impl.** | forensic_findings.md; risk_register | None | Incident findings, Sigma rules, analysis complete |
| IDENTIFY | ID.RA-06 | Risk responses | Partial | risk_treatment_plan.md | Medium | Plans R-001 through R-005 drafted; no CISO sign-off |
| PROTECT | PR.AA-01 | Identity mgmt | Partial | ir_playbook_index.md | High | IR-only procedures; no proactive IAM or access review |
| PROTECT | PR.AA-05 | Access review | Not Impl. | None | High | No periodic review program; svc_epic_int over-privileged |
| PROTECT | PR.AT-01 | Training | Partial | security_awareness_training_status.md | **Critical** | 73% completion; 540 non-compliant; no phishing metrics |
| PROTECT | PR.DS-01 | Encryption | Partial | endpoint_hardening_baseline.md | Medium | BitLocker 173/280 (62%); cloud/devices unencrypted |
| PROTECT | PR.PS-01 | Config baseline | Partial | endpoint_hardening_baseline.md | High | Hardened 231/280 (82%); legacy GPOs conflict |
| PROTECT | PR.PS-04 | Logging | Partial | sigma_detection_catalog.md | High | Sysmon 198/280 (71%); no formal review schedule |
| DETECT | DE.CM-01 | Monitoring | Partial | sigma_detection_catalog.md | High | 9 Sigma rules active; 71% coverage; devices absent |
| DETECT | DE.CM-06 | Provider activity | Partial | forensic_findings.md | High | CloudTrail missing in DR; vendor update control not formalized |
| DETECT | DE.AE-02 | Event analysis | **Impl.** | forensic_findings.md | None | Incident analysis complete; playbooks tested |
| RESPOND | RS.MA-01 | IR plan | Partial | ir_playbook_index.md | High | 3 playbooks tested; cloud and vendor workflows draft |
| RESPOND | RS.AN-03 | Analysis | **Impl.** | forensic_findings.md | None | Forensic analysis complete; timeline and RCA done |
| RESPOND | RS.CO-02 | Communication | Partial | ir_playbook_index.md | High | Internal procedures done; no OCR/board communication plan |
| RECOVER | RC.RP-01 | Recovery | Partial | recovery_validation_summary.md | High | LIS tested; RTO exceeded (41 vs 30 min); AD/Epic untested |
| RECOVER | RC.CO-01 | Recovery comms | Partial | recovery_validation_summary.md | Medium | LIS comms added; no formal multi-system plan |


## Summary

**Status counts:** 4 Implemented (18%), 14 Partial (64%), 4 Not Implemented (18%)

**Top 3 pre-audit blockers:**
1. **GV.PO-01 (Critical)** — Missing AUP, Data Classification, Vendor policies; board approval needed by 2026-06-01
2. **PR.AT-01 (Critical)** — 540 staff non-compliant; phishing metrics absent; target 2026-06-15
3. **PR.AA-01 (High)** — No proactive IAM or access review; svc_epic_int over-privileged

**Governance vs. technical split:**
- 14 "Partial" controls have technical implementations (hardening, detections, playbooks) but lack governance layer (policies, review evidence, formal approval)
- 4 "Not Implemented" controls require enterprise programs (vendor mgmt, access review, IAM) not individual projects

**Remediation timeline:** risk_treatment_plan.md targets 2026-06-01 through 2026-07-01, aligned with OCR pre-audit window.
