#!/bin/bash

STATE_DIR="/tmp/rtest_state"
LOG_FILE="/tmp/meddefense-dr-test/recovery_test_log.txt"
mkdir -p "$STATE_DIR"

if [ ! -f "$LOG_FILE" ]; then
    > "$LOG_FILE"
fi

STEP_NAME="$1"
STATUS="$2"

if [ "$STATUS" == "START" ]; then
    START_TIME=$(date '+%H:%M:%S')
    echo "$STEP_NAME" > "$STATE_DIR/current_step"
    echo "$START_TIME" > "$STATE_DIR/current_start"
    echo "▶ $STEP_NAME ... started at $START_TIME"

elif [ "$STATUS" == "PASS" ] || [ "$STATUS" == "FAIL" ]; then
    START_TIME=$(cat "$STATE_DIR/current_start" 2>/dev/null)
    END_TIME=$(date '+%H:%M:%S')
    CURRENT_STEP=$(cat "$STATE_DIR/current_step" 2>/dev/null)

    # Calculate duration in seconds
    START_SEC=$(date -d "2000-01-01 $START_TIME" +%s 2>/dev/null || echo 0)
    END_SEC=$(date -d "2000-01-01 $END_TIME" +%s 2>/dev/null || echo 0)
    DURATION=$((END_SEC - START_SEC))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))

    STEP_NUM=$(grep -c "^\[STEP" "$LOG_FILE")
    STEP_NUM=$((STEP_NUM + 1))

    printf "[STEP %02d] %-30s | Start: %s | End: %s | Duration: %dm %02ds | %s\n" \
        "$STEP_NUM" "$CURRENT_STEP" "$START_TIME" "$END_TIME" "$MINUTES" "$SECONDS" "$STATUS" >> "$LOG_FILE"

    echo "✓ $CURRENT_STEP completed in ${MINUTES}m ${SECONDS}s [$STATUS]"

elif [ "$STATUS" == "SUMMARY" ]; then
    echo ""
    echo "====== RECOVERY TEST SUMMARY ======"
    cat "$LOG_FILE"

    # Calculate total time
    FIRST_START=$(head -1 "$LOG_FILE" | grep -oP 'Start: \K[^|]+' || echo "N/A")
    LAST_END=$(tail -1 "$LOG_FILE" | grep -oP 'End: \K[^|]+' || echo "N/A")

    if [ "$FIRST_START" != "N/A" ] && [ "$LAST_END" != "N/A" ]; then
        FIRST_SEC=$(date -d "2000-01-01 $FIRST_START" +%s 2>/dev/null || echo 0)
        LAST_SEC=$(date -d "2000-01-01 $LAST_END" +%s 2>/dev/null || echo 0)
        TOTAL=$((LAST_SEC - FIRST_SEC))
        TOTAL_MIN=$((TOTAL / 60))
        TOTAL_SEC=$((TOTAL % 60))

        echo ""
        echo "Total Recovery Time: ${TOTAL_MIN}m ${TOTAL_SEC}s"
        echo "Declared RTO: 30 minutes"

        if [ $TOTAL -le 1800 ]; then
            echo " RTO MET (within 30 minutes)"
        else
            echo " RTO FAILED (exceeded 30 minutes)"
        fi
    fi
    echo "===================================="
fi
