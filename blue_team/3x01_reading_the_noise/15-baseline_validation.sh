#!/bin/bash

set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY_FILE="$BASELINE_PKG/baseline_summary.json"
OUT_FILE="$BASELINE_PKG/baseline_validation.json"

python3 -W error - "$BASELINE_PKG" "$SUMMARY_FILE" "$OUT_FILE" << 'PYTHON_EOF'
import sys, os, json, subprocess

base_pkg, summary_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(summary_path, 'r', encoding='utf-8') as f:
    summary = json.load(f)

baseline_win = summary.get("baseline_window", {})
eval_win = summary.get("evaluation_window", {})

def run_pass(tag):
    auth_out = os.path.join(base_pkg, f"{tag}_check_auth.json")
    proc_out = os.path.join(base_pkg, f"{tag}_check_process.json")
    
    subprocess.run(["bash", os.path.join(base_pkg, "10-anomalies_auth.sh")], cwd=base_pkg, capture_output=True)
    if os.path.exists(os.path.join(base_pkg, "anomalies_auth.json")):
        os.replace(os.path.join(base_pkg, "anomalies_auth.json"), auth_out)
        
    subprocess.run(["bash", os.path.join(base_pkg, "11-anomalies_process.sh")], cwd=base_pkg, capture_output=True)
    if os.path.exists(os.path.join(base_pkg, "anomalies_process.json")):
        os.replace(os.path.join(base_pkg, "anomalies_process.json"), proc_out)

    total, breakdown = 0, {}
    for path in [auth_out, proc_out]:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as pf:
                try:
                    data = json.load(pf)
                    for item in data:
                        total += 1
                        atype = item.get("anomaly_type", "unknown")
                        breakdown[atype] = breakdown.get(atype, 0) + 1
                except:
                    pass
    return total, breakdown

summary["evaluation_window"] = {"start": baseline_win.get("start"), "end": baseline_win.get("end")}
with open(summary_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)

self_total, self_breakdown = run_pass("self")

summary["evaluation_window"] = eval_win
with open(summary_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)

live_total, live_breakdown = run_pass("live")

signal_to_noise = round(live_total / max(self_total, 1), 2)
verdict = "pass" if self_total < 5 and (live_total > 0 or signal_to_noise >= 3.0) else "fail"
if self_total < 5 and live_total > 0:
    verdict = "pass"

validation_output = {
    "self_check_total": self_total,
    "self_check_breakdown": self_breakdown,
    "live_check_total": live_total,
    "live_check_breakdown": live_breakdown,
    "signal_to_noise_ratio": signal_to_noise,
    "verdict": verdict
}

with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(validation_output, f, indent=2)

print(f"self-check anomalies (baseline window): {self_total}")
print(f"live-check anomalies (evaluation win ): {live_total}")
print(f"signal-to-noise ratio                : {signal_to_noise}")
print(f"verdict                              : {verdict}")
print("baseline_validation.json written")

sys.exit(0 if verdict == "pass" else 1)
PYTHON_EOF