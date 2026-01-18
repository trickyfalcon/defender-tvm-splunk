#!/bin/bash
# Defender TVM DELTA Export to Splunk
# Fetches vulnerability changes (New/Fixed/Updated) from last 25 hours
# Sourcetype: defender:tvm:delta
# Schedule: Daily at 5:00 AM

set -e

SCRIPT_DIR="/opt/Defender-splunk"
LOG_FILE="/var/log/defender-tvm-delta.log"
LOCK_FILE="/tmp/defender-tvm-delta.lock"

CERT_PATH="${SCRIPT_DIR}/defender-tvm.crt"
KEY_PATH="${SCRIPT_DIR}/defender-tvm.key"

# Prevent concurrent runs
if [ -f "$LOCK_FILE" ]; then
    echo "$(date -Iseconds) ERROR: Another delta instance is running" >> "$LOG_FILE"
    exit 1
fi
trap "rm -f $LOCK_FILE" EXIT
touch "$LOCK_FILE"

echo "$(date -Iseconds) INFO: Starting Defender TVM DELTA export" >> "$LOG_FILE"

cd "$SCRIPT_DIR"

python3 defender-tvm-delta.py \
    --cert-path "$CERT_PATH" \
    --key-path "$KEY_PATH" \
    --since-hours 25 \
    --include-catalog \
    --send-hec \
    --api-sleep 1.0 \
    --hec-batch-size 500 \
    --continue-on-error \
    >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date -Iseconds) INFO: Defender TVM DELTA export completed successfully" >> "$LOG_FILE"
else
    echo "$(date -Iseconds) ERROR: Defender TVM DELTA export failed with exit code $EXIT_CODE" >> "$LOG_FILE"
fi

exit $EXIT_CODE
