#!/bin/bash
# start.sh — start or restart the anti-scam bot

BOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$BOT_DIR/antiscam.pid"
LOG_FILE="$BOT_DIR/antiscam.log"

# Kill existing
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Stopping old process ($OLD_PID)..."
        kill "$OLD_PID"
        sleep 1
    fi
fi

echo "Starting CKB Anti-Scam Bot..."
cd "$BOT_DIR"
nohup node antiscam.js >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "Started (PID: $(cat $PID_FILE))"
echo "Log: tail -f $LOG_FILE"
