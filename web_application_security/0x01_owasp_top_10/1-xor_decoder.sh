#!/bin/bash

data="${1//\{xor\}/}"

decoded=$(base64 -d <<< "$data")

result=""

for ((i=0; i<${#decoded}; i++)); do
    byte=$(printf '%d' "'${decoded:$i:1}")
    xor=$((byte ^ 0x5f))
    result+=$(printf "\\$(printf '%03o' "$xor")")
done

printf '%s\n' "$result"
