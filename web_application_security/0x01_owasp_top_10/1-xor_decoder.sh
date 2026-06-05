#!/bin/bash

d="${1//\{xor\}/}"
b=$(printf '%s' "$d" | base64 -d 2>/dev/null)

for ((i=0;i<${#b};i++)); do
    printf "\\$(printf '%03o' "$(( $(printf '%d' "'${b:i:1}") ^ 95 ))")"
done

echo
