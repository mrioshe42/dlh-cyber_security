#!/bin/bash

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v sigma >/dev/null 2>&1; then
    for rule in "$DIR"/sigma_*.yml; do
        sigma check "$rule" >/dev/null || { echo "sigma check failed: $rule"; exit 1; }
    done
else
    echo "sigma-cli not installed; skipping schema check (pip install sigma-cli)"
fi

python3 - "$DIR" <<'PY'
import fnmatch, glob, json, os, re, sys

import yaml

root = sys.argv[1]
SAMPLES = {
    "incident_sysmon.jsonl": os.path.join(root, "5x03", "incident_sysmon.jsonl"),
    "clean_sysmon.jsonl": os.path.join(root, "5x03", "clean_sysmon.jsonl"),
}
FP_TARGET_PCT = 0.1
CATEGORY_EVENT_ID = {"process_creation": 1, "network_connection": 3, "file_event": 11, "registry_set": 13}


def load(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def flat(e):
    # Map the sample's field names onto the Sysmon field names Sigma rules use.
    return {
        "EventID": e.get("event_id"),
        "Image": e.get("image"),
        "ParentImage": e.get("parent_image"),
        "CommandLine": e.get("cmdline"),
        "DestinationIp": e.get("dst_ip"),
        "DestinationHostname": e.get("dst_hostname"),
        "TargetObject": e.get("target_object"),
        "User": e.get("user"),
    }


def match_value(actual, modifier, expected):
    if actual is None:
        return False
    a, x = str(actual).lower(), str(expected).lower()
    if modifier == "endswith":
        return a.endswith(x)
    if modifier == "startswith":
        return a.startswith(x)
    if modifier == "contains":
        return x in a
    return a == x


def match_selection(event, selection):
    # A list of maps is an OR; a map is an AND of its fields; a list of values inside a field is an OR.
    if isinstance(selection, list):
        return any(match_selection(event, s) for s in selection)
    for key, expected in selection.items():
        name, _, modifier = key.partition("|")
        values = expected if isinstance(expected, list) else [expected]
        if not any(match_value(event.get(name), modifier or "equals", v) for v in values):
            return False
    return True


def evaluate(detection, event):
    selections = {k: match_selection(event, v) for k, v in detection.items() if k != "condition"}
    cond = detection["condition"]

    def of_repl(m):
        count, pattern = m.group(1), m.group(2)
        hits = [selections[k] for k in selections if fnmatch.fnmatch(k, pattern)]
        ok = all(hits) if count == "all" else sum(hits) >= int(count)
        return str(ok)

    cond = re.sub(r"\b(\d+|all) of ([A-Za-z0-9_*]+)", of_repl, cond)
    expr = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                  lambda m: str(selections[m.group(0)]) if m.group(0) in selections else m.group(0), cond)
    return bool(eval(expr, {"__builtins__": {}}, {}))


overall_ok = True
rules = sorted(glob.glob(os.path.join(root, "sigma_*.yml")))
if not rules:
    print("No sigma_*.yml rules found")
    sys.exit(1)

for rule_path in rules:
    with open(rule_path) as f:
        rule = yaml.safe_load(f)
    category = (rule.get("logsource") or {}).get("category")
    event_id = CATEGORY_EVENT_ID.get(category)
    print(f"== {os.path.basename(rule_path)}: {rule.get('title')} ==")

    for name, path in SAMPLES.items():
        events = load(path)
        total = len(events)
        hits = [e for e in events
                if (event_id is None or e.get("event_id") == event_id) and evaluate(rule["detection"], flat(e))]
        rate = 100 * len(hits) / total if total else 0.0
        print(f"  [{name}]")
        print(f"  Total events: {total:,}")
        print(f"  Matches: {len(hits)}")
        print(f"  Match rate: {rate:.3f}%")
        if name == "clean_sysmon.jsonl":
            print(f"  False positive rate: {rate:.3f}% (target < {FP_TARGET_PCT}%)")
            verdict = "PASS" if rate < FP_TARGET_PCT else "REVIEW"
            for e in hits:
                print(f"    - {e['ts']} {e['host']} {e.get('parent_image')} -> {e.get('image')}")
        else:
            verdict = "PASS" if hits else "FAIL"
            for e in hits:
                print(f"    - {e['ts']} {e['host']} PID {e.get('pid')}: {e.get('image')}")
        print(f"  Verdict: {verdict}")
        if verdict != "PASS":
            overall_ok = False

sys.exit(0 if overall_ok else 1)
PY
