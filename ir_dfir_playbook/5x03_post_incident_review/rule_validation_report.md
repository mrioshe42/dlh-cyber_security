# Rule Validation Report: IR-2026-0414-01

Run: `./validate_rules.sh` (with sigma-cli on PATH, the schema check also passes). Exit status 0.

## Results

| Rule | Sample | Events | Matches | Match rate | Verdict |
|---|---|---|---|---|---|
| sigma_powershell_msbuild_lolbin.yml | incident_sysmon.jsonl | 17 | 2 | 11.765% | PASS |
| sigma_powershell_msbuild_lolbin.yml | clean_sysmon.jsonl | 21 | 0 | 0.000% (FP rate) | PASS (target < 0.1%) |

Matched events on the incident sample:
- 2026-04-14T02:46:58Z, WST-WS-031, PID 8104: `powershell.exe` -> `MSBuild.exe`
- 2026-04-14T03:27:13Z, WST-WS-017, PID 5108: `powershell.exe` -> `MSBuild.exe`

## Answers to the validation questions

- **Did the rule fire on the incident data?** Yes. It fires on both MSBuild launches from PowerShell, on WST-WS-031 and WST-WS-017.
- **False positive rate on the clean baseline?** 0.000% (0 of 21 events). The target is under 0.1%.
- **Tuning required?** No. The clean sample produced no matches, so the rule was not changed and no tuned version was needed.

## Limits of this validation

- **The samples are small.** The incident sample has 17 events and the clean sample has 21. The clean sample has 7 process-creation events, so a 0% rate here says little about the rule's real-world false positive rate. The brief describes a 30-day baseline with about 287k events. The file in the repo is an extract, so the 0% figure is not a production estimate.
- **The clean sample has no PowerShell-spawned MSBuild.** The developer MSBuild events in it come from `devenv.exe`, not PowerShell. The rule's documented false positives (deploy scripts calling MSBuild, PowerShell wrappers around `csc.exe`) are not represented in the sample, so they remain untested.
- **Only one rule exists.** The brief asks for both the Task 3 and Task 4 rules. The Task 4 rule (network) is not in this directory, so the script only tested the Task 3 rule. The 14 clean-baseline network events to `api.nuget.org` that the brief describes would only matter to that rule.
- **Sigma-cli is optional.** The script runs the `sigma check` schema step only if sigma-cli is on PATH. Without it, the script skips that step and says so. The matcher is a small evaluator written for this script, not sigma-cli itself, because sigma-cli has no local event-matching backend.

## Changes made

None to the rule. The validation found no false positives to tune.
