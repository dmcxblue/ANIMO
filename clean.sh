#!/usr/bin/env bash
#
# clean.sh - wipe ANIMO runtime state for a clean testing slate.
#
# Removes databases, per-session data, logs, command history, and the encrypted
# auto-restore file (saved_sessions.dat) so the next run starts with nothing
# carried over. Source code and compiled binaries are left untouched.
#
# Usage:
#   ./clean.sh            # remove runtime data (asks for confirmation)
#   ./clean.sh -y         # skip the confirmation prompt
#   ./clean.sh -n         # dry run: show what would be removed, delete nothing
#   ./clean.sh -s         # ALSO clear client UI settings (~/.config/ANIMO)
#   ./clean.sh -b         # ALSO remove the build/ directory (forces a full rebuild)
#   ./clean.sh -d PATH    # ALSO clean a custom server data dir (server -d PATH)
#   ./clean.sh -h         # help
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Safety: never operate on an empty or root path.
if [[ -z "$ROOT" || "$ROOT" == "/" ]]; then
    echo "[!] Refusing to run: repository root resolved to '$ROOT'." >&2
    exit 1
fi

ASSUME_YES=0
DRY_RUN=0
WIPE_SETTINGS=0
WIPE_BUILD=0
EXTRA_DATA_DIR=""

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)      ASSUME_YES=1 ;;
        -n|--dry-run)  DRY_RUN=1 ;;
        -s|--settings) WIPE_SETTINGS=1 ;;
        -b|--build)    WIPE_BUILD=1 ;;
        -d|--data-dir) EXTRA_DATA_DIR="${2:-}"; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "[!] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

# ── Build the list of targets that actually exist ───────────────────────────
targets=()

add_if_exists() { if [[ -e "$1" ]]; then targets+=("$1"); fi; return 0; }
add_glob()      { local g; for g in $1; do if [[ -e "$g" ]]; then targets+=("$g"); fi; done; return 0; }

# Runtime data directories (CWD-relative and binary-relative).
add_if_exists "$ROOT/data"
add_if_exists "$ROOT/build/server/data"
add_if_exists "$ROOT/build/client/data"

# Stray runtime files that can land at the repo root depending on the launch dir.
add_glob "$ROOT/*.db"
add_glob "$ROOT/*.db-wal"
add_glob "$ROOT/*.db-shm"
add_glob "$ROOT/*.db-journal"
add_glob "$ROOT/error.log"
add_glob "$ROOT/error.log.*"
add_glob "$ROOT/history_*.txt"
add_glob "$ROOT/*.animosession"
add_glob "$ROOT/*.animosessions"
add_glob "$ROOT/saved_sessions.dat"

# Optional: a custom server data dir (server -d PATH).
if [[ -n "$EXTRA_DATA_DIR" ]]; then
    if [[ "$EXTRA_DATA_DIR" == "/" || "$EXTRA_DATA_DIR" == "$HOME" ]]; then
        echo "[!] Refusing to clean unsafe data dir: '$EXTRA_DATA_DIR'." >&2
        exit 1
    fi
    add_if_exists "$EXTRA_DATA_DIR"
fi

# Optional: client UI settings (window geometry, preferences).
if [[ "$WIPE_SETTINGS" -eq 1 ]]; then
    add_if_exists "$HOME/.config/ANIMO"
fi

# Optional: build output.
if [[ "$WIPE_BUILD" -eq 1 ]]; then
    add_if_exists "$ROOT/build"
fi

# ── Report / confirm / delete ───────────────────────────────────────────────
if [[ ${#targets[@]} -eq 0 ]]; then
    echo "[*] Nothing to clean - already a fresh slate."
    exit 0
fi

echo "The following ANIMO runtime state will be removed:"
for t in "${targets[@]}"; do
    size="$(du -sh "$t" 2>/dev/null | cut -f1 || echo '?')"
    printf '  - %s  (%s)\n' "$t" "$size"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[*] Dry run - nothing was deleted."
    exit 0
fi

if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Proceed? [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "[*] Aborted."; exit 0 ;;
    esac
fi

for t in "${targets[@]}"; do
    rm -rf -- "$t"
    echo "  removed $t"
done

echo "[+] Clean slate ready."
