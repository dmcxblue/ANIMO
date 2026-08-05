#!/usr/bin/env bash
#
# clean.sh - wipe ANIMO build output and runtime state for a clean slate.
#
# Removes the build/ directory plus databases, per-session data, logs, command
# history, and the encrypted auto-restore file (saved_sessions.dat) so the next
# run starts with nothing carried over. Also sweeps generated compile artifacts
# (moc_*, *_autogen/, CMakeFiles/, ...) that an in-source build can leave behind
# in client/, server/ and shared/. Tracked source files are never touched.
#
# Usage:
#   ./clean.sh            # remove build/ + runtime data (asks for confirmation)
#   ./clean.sh -y         # skip the confirmation prompt
#   ./clean.sh -n         # dry run: show what would be removed, delete nothing
#   ./clean.sh -B         # KEEP the build/ directory (runtime data only)
#   ./clean.sh -s         # ALSO clear client UI settings (~/.config/ANIMO)
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
WIPE_BUILD=1          # build/ is removed by default; -B keeps it
EXTRA_DATA_DIR=""

usage() { sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)        ASSUME_YES=1 ;;
        -n|--dry-run)    DRY_RUN=1 ;;
        -s|--settings)   WIPE_SETTINGS=1 ;;
        -b|--build)      WIPE_BUILD=1 ;;   # kept for muscle memory; now the default
        -B|--keep-build) WIPE_BUILD=0 ;;
        -d|--data-dir)   EXTRA_DATA_DIR="${2:-}"; shift ;;
        -h|--help)       usage; exit 0 ;;
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
add_glob "$ROOT/device_certs.dat"

# ── Generated compile artifacts left in the source tree ─────────────────────
# An accidental in-source cmake run (`cmake .`) scatters moc_*.cpp, *_autogen/,
# CMakeFiles/ and friends next to the sources. These are pure build output and
# must never reach git, so sweep them too. Anything git tracks is skipped, so a
# real source file can never be deleted by a name collision.
HAVE_GIT=0
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    HAVE_GIT=1
fi

is_tracked() {
    [[ "$HAVE_GIT" -eq 1 ]] && git -C "$ROOT" ls-files --error-unmatch -- "$1" >/dev/null 2>&1
}

sweep_generated() {
    local dir="$1" p
    [[ -d "$dir" ]] || return 0
    while IFS= read -r -d '' p; do
        is_tracked "$p" && continue
        targets+=("$p")
    done < <(find "$dir" \
        \( -name '.git' -o -name 'build' \) -prune -o \
        \( -name 'moc_*.cpp'      -o -name 'moc_*.h'          \
        -o -name 'moc_predefs.h'  -o -name 'mocs_compilation*' \
        -o -name 'qrc_*.cpp'      -o -name 'ui_*.h'            \
        -o -name '*_autogen'      -o -name 'CMakeFiles'        \
        -o -name 'CMakeCache.txt' -o -name 'cmake_install.cmake' \
        -o -name 'CTestTestfile.cmake' -o -name 'install_manifest.txt' \
        -o -name '.qt'            -o -name '.ninja_*'          \
        -o -name 'build.ninja'    -o -name 'Makefile'          \
        -o -name '*.o'            -o -name '*.a'               \
        -o -name '*.so'           -o -name '*.so.*'            \
        \) -print0 2>/dev/null)
}

for d in "$ROOT/client" "$ROOT/server" "$ROOT/shared" "$ROOT/helpers"; do
    sweep_generated "$d"
done
# Same artifacts at the repo root (from `cmake .` in the checkout root).
for f in CMakeCache.txt CMakeFiles cmake_install.cmake CTestTestfile.cmake \
         install_manifest.txt build.ninja .ninja_deps .ninja_log .qt \
         Makefile compile_commands.json AnimoServer AnimoClient; do
    if [[ -e "$ROOT/$f" ]] && ! is_tracked "$ROOT/$f"; then
        targets+=("$ROOT/$f")
    fi
done

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

if [[ "$WIPE_BUILD" -eq 1 ]]; then
    echo "The following ANIMO build output and runtime state will be removed:"
else
    echo "The following ANIMO runtime state will be removed (build/ kept):"
fi
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
