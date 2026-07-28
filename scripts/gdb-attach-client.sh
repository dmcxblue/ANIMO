#!/usr/bin/env bash
# gdb-attach-client.sh
# ---------------------------------------------------------------------------
# Attach gdb to the running AnimoClient (or run it under gdb) so any crash
# lands a full backtrace at a predictable log path for post-mortem analysis.
#
# Two modes:
#   1) If AnimoClient is already running, does a live snapshot: pauses briefly,
#      prints threads + full backtrace of every thread, detaches. Non-invasive.
#   2) If AnimoClient is not running, spawns it under gdb in batch mode so any
#      later crash automatically dumps the backtrace before gdb exits.
#
# Output goes to:
#   /tmp/animo-cli-gdb.log        (this script's snapshot / crash output)
#   /tmp/animo-cli-dbg.log        (client's own qInfo mirror, installed in main)
#   /tmp/animo-srv-dbg.log        (server's own qInfo mirror)
#
# Usage:
#   ./scripts/gdb-attach-client.sh              # auto: snapshot if running, else spawn
#   ./scripts/gdb-attach-client.sh --snapshot   # force snapshot on running proc
#   ./scripts/gdb-attach-client.sh --spawn      # kill existing, spawn under gdb
# ---------------------------------------------------------------------------

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
CLIENT_BIN="$REPO_ROOT/build/client/AnimoClient"
LOG="/tmp/animo-cli-gdb.log"

MODE="${1:-auto}"

require_gdb() {
    command -v gdb >/dev/null || { echo "gdb not on PATH"; exit 1; }
}

snapshot() {
    local pid="$1"
    echo "[*] Attaching to AnimoClient pid=$pid for live snapshot..."
    {
        echo
        echo "===== $(date -Iseconds)  live-snapshot  pid=$pid ====="
        gdb -batch -nx -p "$pid" \
            -ex "set pagination off" \
            -ex "set print thread-events off" \
            -ex "set print pretty on" \
            -ex "info threads" \
            -ex "thread apply all bt 60" 2>&1
    } | tee -a "$LOG"
    echo
    echo "[+] Snapshot appended to $LOG"
    echo "[*] Client should have resumed. Verify with: pgrep -x AnimoClient"
}

spawn_under_gdb() {
    [ -x "$CLIENT_BIN" ] || { echo "Client binary not found: $CLIENT_BIN"; exit 1; }
    echo "[*] Killing any running AnimoClient..."
    pkill -x AnimoClient 2>/dev/null
    sleep 1
    echo "[*] Spawning AnimoClient under gdb - any crash will dump full backtrace to $LOG"
    : > "$LOG"
    cd "$REPO_ROOT" || exit 1
    gdb -batch -nx \
        -ex "set pagination off" \
        -ex "set print pretty on" \
        -ex "set print thread-events off" \
        -ex "handle SIGPIPE nostop noprint pass" \
        -ex "run" \
        -ex "bt full" \
        -ex "info threads" \
        -ex "thread apply all bt 60" \
        "$CLIENT_BIN" 2>&1 | tee -a "$LOG"
    echo
    echo "[+] gdb exited. Backtrace (if any) is in $LOG"
}

require_gdb
RUNNING=$(pgrep -x AnimoClient | head -1)

case "$MODE" in
    --snapshot|snapshot)
        [ -n "$RUNNING" ] || { echo "AnimoClient not running - can't snapshot."; exit 1; }
        snapshot "$RUNNING"
        ;;
    --spawn|spawn)
        spawn_under_gdb
        ;;
    auto|*)
        if [ -n "$RUNNING" ]; then
            snapshot "$RUNNING"
        else
            spawn_under_gdb
        fi
        ;;
esac
