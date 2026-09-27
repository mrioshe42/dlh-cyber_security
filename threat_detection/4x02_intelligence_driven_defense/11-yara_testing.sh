#!/bin/bash
DIR="4x02/samples"

if [ ! -d "$DIR" ]; then echo "Error: $DIR not found"; exit 1; fi
if ! command -v yara &> /dev/null; then echo "Error: yara not installed"; exit 1; fi

eval_rule() {
    local rule=$1 name=$2 filter=$3 tp=0 tn=0 fp=0 fn=0
    
    for f in "$DIR"/$filter; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        
        if [[ "$base" =~ (phishing_sample|healthbane_lure_02|healthbane_email_01|healthbane_email_02) ]]; then
            exp=1
        else
            exp=0
        fi
        
        if yara "$rule" "$f" 2>/dev/null \vert{} grep -q "$name"; then
            if [ "$exp" -eq 1 ]; then ((tp++)); else ((fp++)); fi
        else
            if [ "$exp" -eq 1 ]; then ((fn++)); else ((tn++)); fi
        fi
    done

    awk -v r="$name" -v tp="$tp" -v tn="$tn" -v fp="$fp" -v fn="$fn" 'BEGIN {
        dr = (tp+fn>0) ? (tp/(tp+fn))*100 : 0
        fpr = (fp+tn>0) ? (fp/(fp+tn))*100 : 0
        pr = (tp+fp>0) ? (tp/(tp+fp))*100 : 0
        
        printf "\nRule: %s\nTP: %d | TN: %d | FP: %d | FN: %d\n", r, tp, tn, fp, fn
        printf "Detection rate: %.0f%%\nFalse positive rate: %.0f%%\nPrecision: %.0f%%\n", dr, fpr, pr
        if (fpr > 0 || fn > 0) print "Recommendation: TUNE"
        else print "Recommendation: DEPLOY"
    }'
}

echo "=== YARA TESTING SUMMARY ==="

eval_rule "9-yara_phishing_pdf.yar" "HEALTHBANE_Phishing_PDF" "*.pdf"
eval_rule "10-yara_arsenal.yar" "HEALTHBANE_Email_Headers" "*.eml"
eval_rule "9-yara_phishing_pdf.yar" "HEALTHBANE_Campaign_Composite" "all"
