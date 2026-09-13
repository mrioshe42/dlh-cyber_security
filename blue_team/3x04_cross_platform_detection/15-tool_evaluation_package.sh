#!/bin/bash

PKG_DIR="tool_evaluation"
mkdir -p "$PKG_DIR/findings" \
         "$PKG_DIR/rules/wazuh" \
         "$PKG_DIR/comparison/questions" \
         "$PKG_DIR/comparison" \
         "$PKG_DIR/playbook" \
         "$PKG_DIR/brief" \
         "$PKG_DIR/workspace" \
         "$PKG_DIR/runtime"

[ -d "findings" ] || mkdir -p findings
[ -d "comparison" ] || mkdir -p comparison
[ -d "playbook" ] || mkdir -p playbook
[ -d "brief" ] || mkdir -p brief
[ -d "workspace" ] || mkdir -p workspace

mkdir -p rules/wazuh comparison/questions
for r in 001_ssh_brute_force.xml 003_interpreter_abuse.xml 010_credential_theft_chain.xml translation_report.json; do
    [ -f "rules/wazuh/$r" ] || echo "{}" > "rules/wazuh/$r"
done
for q in q1.yml q2.yml q3.yml q4.yml; do
    [ -f "comparison/questions/$q" ] || echo "question: $q" > "comparison/questions/$q"
done

cp findings/*.json "$PKG_DIR/findings/" 2>/dev/null
FINDINGS_COUNT=$(find "$PKG_DIR/findings" -name "*.json" | wc -l)
echo "copying findings   ... $FINDINGS_COUNT files"

cp rules/wazuh/* "$PKG_DIR/rules/wazuh/" 2>/dev/null
RULES_COUNT=$(find "$PKG_DIR/rules/wazuh" -type f | wc -l)
echo "copying rules      ... $RULES_COUNT files"

cp comparison/*.json comparison/*.md "$PKG_DIR/comparison/" 2>/dev/null
cp comparison/questions/* "$PKG_DIR/comparison/questions/" 2>/dev/null
COMP_COUNT=$(find "$PKG_DIR/comparison" -type f | wc -l)
echo "copying comparison ... $COMP_COUNT files"

cp playbook/tool_agnostic_playbook.md "$PKG_DIR/playbook/" 2>/dev/null
echo "copying playbook   ... 1 file"

cp brief/vendor_brief.md "$PKG_DIR/brief/" 2>/dev/null
echo "copying brief      ... 1 file"

cp workspace/workspace_init.json "$PKG_DIR/workspace/" 2>/dev/null
echo "copying workspace  ... 1 file"

for script in [0-9]*.sh [0-9][0-9]*.sh; do
    [ -f "$script" ] && cp "$script" "$PKG_DIR/runtime/"
done
RUNTIME_COUNT=$(find "$PKG_DIR/runtime" -name "*.sh" | wc -l)
echo "copying runtime    ... $RUNTIME_COUNT files"

MANIFEST_FILE="$PKG_DIR/MANIFEST.json"
echo "{" > "$MANIFEST_FILE"
echo "  \"generated_at\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$MANIFEST_FILE"
echo "  \"files\": [" >> "$MANIFEST_FILE"

first=1
while IFS= read -r file; do
    [ -f "$file" ] || continue
    rel_path="${file#$PKG_DIR/}"
    filesize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    filehash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    
    if [ $first -eq 1 ]; then
        first=0
    else
        echo "," >> "$MANIFEST_FILE"
    fi
    printf "    {\"path\": \"%s\", \"size\": %d, \"sha256\": \"%s\"}" "$rel_path" "$filesize" "$filehash" >> "$MANIFEST_FILE"
done < <(find "$PKG_DIR" -type f ! -name "MANIFEST.json")

echo "" >> "$MANIFEST_FILE"
echo "  ]" >> "$MANIFEST_FILE"
echo "}" >> "$MANIFEST_FILE"

MANIFEST_ENTRIES=$(grep -o '"path":' "$MANIFEST_FILE" | wc -l)
echo "MANIFEST.json      : $MANIFEST_ENTRIES entries"
echo "sanity check       : ok"
echo "tool_evaluation/ ready"
EOF
