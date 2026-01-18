#!/bin/bash
# Defender TVM BULK Export to Splunk
# Fetches ALL current vulnerabilities (full snapshot)
# Sourcetype: defender:tvm:bulk
# Schedule: Daily at 5:30 AM (after delta)

set -e

SCRIPT_DIR="/opt/Defender-splunk"
LOG_FILE="/var/log/defender-tvm-bulk.log"
LOCK_FILE="/tmp/defender-tvm-bulk.lock"

CERT_PATH="${SCRIPT_DIR}/defender-tvm.crt"
KEY_PATH="${SCRIPT_DIR}/defender-tvm.key"

# Prevent concurrent runs
if [ -f "$LOCK_FILE" ]; then
    echo "$(date -Iseconds) ERROR: Another bulk instance is running" >> "$LOG_FILE"
    exit 1
fi
trap "rm -f $LOCK_FILE" EXIT
touch "$LOCK_FILE"

echo "$(date -Iseconds) INFO: Starting Defender TVM BULK export" >> "$LOG_FILE"

cd "$SCRIPT_DIR"

python3 defender-tvm-bulk.py \
    --cert-path "$CERT_PATH" \
    --key-path "$KEY_PATH" \
    --include-catalog \
    --send-hec \
    --api-sleep 1.0 \
    --hec-batch-size 500 \
    --continue-on-error \
    >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date -Iseconds) INFO: Defender TVM BULK export completed successfully" >> "$LOG_FILE"
else
    echo "$(date -Iseconds) ERROR: Defender TVM BULK export failed with exit code $EXIT_CODE" >> "$LOG_FILE"
fi

exit $EXIT_CODE
