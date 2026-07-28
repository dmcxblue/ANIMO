#!/usr/bin/env bash
# gdb-attach-server.sh
# ---------------------------------------------------------------------------
# Attach gdb to the running AnimoServer, OR spawn it under gdb so any later
# crash is captured with a full backtrace.
#
# Two modes:
#   1) If AnimoServer is already running, does a live snapshot: pauses briefly,
#      prints threads + full backtrace of every thread, detaches. Non-invasive.
#   2) If AnimoServer is not running, spawns it under gdb in batch mode with
#      the passed CLI args. Any crash dumps full backtrace before gdb exits.
#
# Server args:
#   Pass everything after `--` and it's forwarded verbatim to AnimoServer.
#   Or set env: ANIMO_IP, ANIMO_PORT, ANIMO_PASSWORD.
#   Defaults: -i 192.168.1.27 -p 50500 -P rt2025
#
# Output goes to:
#   /tmp/animo-srv-gdb.log        (this script's snapshot / crash output)
#   /tmp/animo-srv-dbg.log        (server's own qInfo mirror, installed in main)
#
# Usage:
#   ./scripts/gdb-attach-server.sh              # auto: snapshot if running, else spawn
#   ./scripts/gdb-attach-server.sh --snapshot   # force snapshot on running proc
#   ./scripts/gdb-attach-server.sh --spawn      # kill existing, spawn under gdb
#   ./scripts/gdb-attach-server.sh --spawn -- -i 0.0.0.0 -p 7777 -P pass
# ---------------------------------------------------------------------------

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
SERVER_BIN="$REPO_ROOT/build/server/AnimoServer"
LOG="/tmp/animo-srv-gdb.log"

# Defaults, overridable via env or CLI passthrough.
IP="${ANIMO_IP:-192.168.1.27}"
PORT="${ANIMO_PORT:-50500}"
PASSWORD="${ANIMO_PASSWORD:-rt2025}"

MODE="auto"
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --snapshot|snapshot) MODE="snapshot"; shift ;;
        --spawn|spawn)       MODE="spawn"; shift ;;
        --) shift; PASSTHROUGH+=("$@"); break ;;
        *)  PASSTHROUGH+=("$1"); shift ;;
    esac
done

# If nothing passed after `--`, build default arg list.
if [ ${#PASSTHROUGH[@]} -eq 0 ]; then
    PASSTHROUGH=(-i "$IP" -p "$PORT" -P "$PASSWORD")
fi

require_gdb() {
    command -v gdb >/dev/null || { echo "gdb not on PATH"; exit 1; }
}

# Match only the "real" AnimoServer for our port/config (not the 7799 test stragglers).
find_running() {
    pgrep -a AnimoServer 2>/dev/null | awk -v p="$PORT" '$0 ~ ("port " p) || $0 ~ ("-p " p) || $0 ~ ("--port " p) {print $1; exit}'
}

snapshot() {
    local pid="$1"
    echo "[*] Attaching to AnimoServer pid=$pid for live snapshot..."
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
    echo "[*] Server should have resumed. Verify with: pgrep -a AnimoServer"
}

spawn_under_gdb() {
    [ -x "$SERVER_BIN" ] || { echo "Server binary not found: $SERVER_BIN"; exit 1; }
    # Kill only the server matching our port; leave unrelated instances alone.
    local existing
    existing=$(find_running)
    if [ -n "$existing" ]; then
        echo "[*] Killing existing AnimoServer pid=$existing (port $PORT)..."
        kill "$existing" 2>/dev/null
        sleep 1
    fi
    echo "[*] Spawning AnimoServer under gdb with args: ${PASSTHROUGH[*]}"
    echo "[*] Crash backtraces will land in $LOG"
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
        --args "$SERVER_BIN" "${PASSTHROUGH[@]}" 2>&1 | tee -a "$LOG"
    echo
    echo "[+] gdb exited. Any backtrace is in $LOG"
}

require_gdb
RUNNING=$(find_running)

case "$MODE" in
    snapshot)
        [ -n "$RUNNING" ] || { echo "AnimoServer not running on port $PORT."; exit 1; }
        snapshot "$RUNNING"
        ;;
    spawn)
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
