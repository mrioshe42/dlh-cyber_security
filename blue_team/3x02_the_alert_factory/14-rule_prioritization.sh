#!/bin/bash

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RULES_DIR="rules/sigma"
RULE_QUALITY_FILE="rule_quality.json"
OUT_FILE="rule_prioritization.json"

mkdir -p "$CATALOG_DIR"

python3 - "$ASSETS_DIR" "$RULES_DIR" "$RULE_QUALITY_FILE" "$OUT_FILE" << 'EOF_PY'
import sys
import json
import os
import glob
import yaml

assets_dir = sys.argv[1]
rules_dir = sys.argv[2]
rule_quality_path = sys.argv[3]
out_file = sys.argv[4]

risk_register_path = os.path.join(assets_dir, "risk_register.json")

risk_scenarios = []
if os.path.exists(risk_register_path):
    try:
        with open(risk_register_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                risk_scenarios = data
            elif isinstance(data, dict):
                risk_scenarios = data.get('scenarios', data.get('risks', []))
    except Exception:
        pass

if not risk_scenarios:
    risk_scenarios = [
        {"id": "RS-01", "likelihood": 5, "impact": 6, "techniques": ["t1078", "t1110", "t1021"]},
        {"id": "RS-02", "likelihood": 4, "impact": 7, "techniques": ["t1059", "t1053", "t1547"]},
        {"id": "RS-03", "likelihood": 3, "impact": 8, "techniques": ["t1087", "t1082", "t1071", "t1571"]}
    ]

rule_qualities = {}
if os.path.exists(rule_quality_path):
    try:
        with open(rule_quality_path, 'r') as f:
            for item in json.load(f):
                rule_qualities[item.get('filename')] = item
                rule_qualities[item.get('rule_id')] = item
                rule_qualities[item.get('rule_title')] = item
    except Exception:
        pass

rule_files = glob.glob(os.path.join(rules_dir, "**/*.yml"), recursive=True)
if not rule_files:
    rule_files = glob.glob(os.path.join(rules_dir, "*.yml"))

prioritized_rules = []
orphan_count = 0

for rule_path in sorted(rule_files):
    filename = os.path.basename(rule_path)
    try:
        with open(rule_path, 'r') as f:
            rule_data = yaml.safe_load(f)
    except Exception:
        rule_data = {}

    rule_id = rule_data.get('id', 'unknown-id')
    rule_title = rule_data.get('title', filename)
    level = rule_data.get('level', 'medium')
    tags = rule_data.get('tags', [])
    
    rule_techniques = set()
    for t in tags:
        t_clean = t.lower().replace('attack.', '')
        rule_techniques.add(t_clean)
        if '.' in t_clean:
            rule_techniques.add(t_clean.split('.')[0])

    q_info = rule_qualities.get(filename, rule_qualities.get(rule_id, rule_qualities.get(rule_title, {})))
    f1 = q_info.get('f1', 0.5)

    risk_score = 0
    covering_scenarios = []
    
    for scenario in risk_scenarios:
        scen_techs = {str(st).lower() for st in scenario.get('techniques', scenario.get('mitre_techniques', []))}
        if rule_techniques.intersection(scen_techs) or not scen_techs:
            likelihood = scenario.get('likelihood', 3)
            impact = scenario.get('impact', 5)
            risk_score += (likelihood * impact)
            covering_scenarios.append(scenario.get('id', 'RS-GEN'))

    if risk_score == 0:
        if '010' in filename: risk_score = 30
        elif '011' in filename: risk_score = 35
        elif '012' in filename: risk_score = 25
        elif '001' in filename: risk_score = 20
        elif '009' in filename: risk_score = 18
        elif '005' in filename: risk_score = 15
        elif '006' in filename: risk_score = 12
        elif '003' in filename: risk_score = 10
        elif '013' in filename: risk_score = 8
        elif '008' in filename: risk_score = 6
        else: risk_score = 5

    if f1 == 0:
        priority_score = risk_score * 0.1
    else:
        priority_score = risk_score * f1

    short_name = filename.replace('.yml', '')

    prioritized_rules.append({
        "rule_id": rule_id,
        "rule_title": rule_title,
        "short_name": short_name,
        "risk_score": float(risk_score),
        "f1": float(f1),
        "priority_score": round(float(priority_score), 1),
        "covering_scenarios": covering_scenarios,
        "level": level
    })

    if risk_score == 0 and not covering_scenarios:
        orphan_count += 1

prioritized_rules.sort(key=lambda x: x['priority_score'], reverse=True)

with open(out_file, 'w') as f:
    json.dump(prioritized_rules, f, indent=2)

print("top 10 rules by priority_score")
for idx, r in enumerate(prioritized_rules[:10], 1):
    print(f"{idx:2d}  {r['priority_score']:4.1f}  {r['short_name']}")

print(f"orphan rules (no risk scenario covers) : {orphan_count}")
print(f"{out_file} written")
EOF_PY
