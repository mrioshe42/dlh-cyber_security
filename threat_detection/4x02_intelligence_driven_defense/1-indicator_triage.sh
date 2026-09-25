#!/bin/bash
# Script Name: 1-indicator_triage.sh

INPUT_JSON="commercial_feed_extract.json"

awk '
BEGIN {
    RS = "}"
    FS = "\n"
    total = 0
    actionable = 0
    contextual = 0
    noise = 0
}

{
    itype = ""
    val = ""
    conf = 50
    tags = ""
    note = ""
    is_indicator = 0

    for (i=1; i<=NF; i++) {
        line = $i
        if (line ~ /"type":/) {
            sub(/.*"type":[ \t]*"/, "", line)
            sub(/".*/, "", line)
            itype = line
            is_indicator = 1
        }
        if (line ~ /"value":/) {
            sub(/.*"value":[ \t]*"/, "", line)
            sub(/".*/, "", line)
            val = line
        }
        if (line ~ /"acme_confidence":/) {
            sub(/.*"acme_confidence":[ \t]*/, "", line)
            sub(/,.*/, "", line)
            conf = line + 0
        }
        if (line ~ /"tags":/) {
            tags = line
        }
        if (line ~ /"acme_note":/) {
            sub(/.*"acme_note":[ \t]*"/, "", line)
            sub(/".*/, "", line)
            note = line
        }
    }

    if (is_indicator && val != "") {
        total++
        
        if (conf < 30 || tags ~ /cdn-shared|microsoft-cloud|cloudflare/ || note ~ /DO NOT BLOCK/) {
            category = "NOISE"
            justification = "Shared cloud/CDN infrastructure or low confidence; high false positive risk."
            uncertainty = "High (Infrastructure shared with benign services)"
            noise++
        } else if ((conf >= 30 && conf < 75) || tags ~ /healthcare-kw|clustered_by_similarity|POSSIBLE_VITALSCORE_PRIOR|shared-hosting/ || note ~ /Predates/) {
            category = "CONTEXTUAL"
            justification = "Historical, pre-campaign staging, or weak similarity match; use for hunting."
            uncertainty = "Medium (Requires manual correlation)"
            contextual++
        } else {
            category = "ACTIONABLE"
            justification = "Confirmed active campaign artifact; safe for perimeter blocklist."
            uncertainty = "Low (High confidence corroboration)"
            actionable++
        }
        printf "[%02d] Type: %-7s | Value: %s\n", total, toupper(itype), val
        printf "     Source: Commercial Feed     | Category: %s\n", category
        printf "     Conf:   %-15s | Uncertainty: %s\n", conf "%", uncertainty
        printf "     Reason: %s\n", justification
    }
}

END {
    printf "Total Indicators Reviewed : %d\n", total
    printf "ACTIONABLE                : %d (%.2f%%)\n", actionable, (total ? (actionable/total)*100 : 0)
    printf "CONTEXTUAL                : %d (%.2f%%)\n", contextual, (total ? (contextual/total)*100 : 0)
    printf "NOISE                     : %d (%.2f%%)\n", noise, (total ? (noise/total)*100 : 0)
}
' "$INPUT_JSON"