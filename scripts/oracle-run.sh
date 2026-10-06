#!/usr/bin/env bash
# Run rct.exe once under the pinned oracle and collect its trace.
#
#   scripts/oracle-run.sh <run-dir> [script] [-- extra env assignments, e.g. RCTHOOK_REALTIME=1]
#
# Every run is independent: a fresh copy of the pristine prefix (game/prefix), its own Xvfb
# display and its own wineserver. Results in <run-dir>: trace.bin, hook.log, wine.log.
# Exit status 0 iff the game reached the script's "quit" (trace ends with TR_FINAL).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$1"; SCRIPT="${2:-}"; shift $(( $# >= 2 ? 2 : 1 ))
[[ "${1:-}" == "--" ]] && shift
EXTRA_ENV=("$@")
TIMEOUT="${ORACLE_TIMEOUT:-600}"

unset TMPDIR   # Ubuntu's Wine 9.0 wineserver aborts ("free(): invalid pointer") when TMPDIR is set
[[ -d "$ROOT/game/prefix" ]] || { echo "no pristine prefix; run scripts/install-native.sh" >&2; exit 2; }
# ORACLE_BIN: directory holding a built dinput.dll (the gate passes a snapshot); default: build.
if [[ -z "${ORACLE_BIN:-}" ]]; then make -s -C "$ROOT/oracle"; ORACLE_BIN="$ROOT/out/oracle-bin"; fi

rm -rf "$RUN"; mkdir -p "$RUN"; RUN="$(cd "$RUN" && pwd)"
# Fresh prefix per run. drive_c/windows (about 580 MB, never written during a run; its files are
# read-only in the pristine prefix) is hard-linked; everything else, including the game directory
# and the registry files the run does write, is copied.
mkdir -p "$RUN/prefix"
tar -C "$ROOT/game/prefix" --exclude=./drive_c/windows -cf - . | tar -C "$RUN/prefix" -xf -
cp -al "$ROOT/game/prefix/drive_c/windows" "$RUN/prefix/drive_c/windows"
[[ -n "$SCRIPT" ]] && cp "$SCRIPT" "$RUN/script.txt"

# Private X display; Xvfb picks a free display number itself (-displayfd), so parallel runs
# cannot collide. Screen geometry is part of the pinned environment: rct.exe sizes its screen
# buffer from it.
exec {DFD}<> <(:)
Xvfb -displayfd "$DFD" -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 & XPID=$!
read -r -t 20 -u "$DFD" DISP || { echo "Xvfb did not start" >&2; exit 2; }
cleanup() {
  WINEPREFIX="$RUN/prefix" wineserver -k 2>/dev/null || true
  kill "$XPID" 2>/dev/null || true
}
trap cleanup EXIT

export DISPLAY=":$DISP" WINEARCH=win32 WINEPREFIX="$RUN/prefix" WINEDEBUG="${WINEDEBUG:-err+all,fixme-all}"
export WINEDLLOVERRIDES="winemenubuilder.exe=d;dinput=n"
winpath() { local p="Z:$1"; echo "${p//\//\\}"; }   # Wine maps Z: to /; no wine call needed
export RCTHOOK_OUT="$(winpath "$RUN")"
[[ -n "$SCRIPT" ]] && export RCTHOOK_SCRIPT="$(winpath "$RUN/script.txt")"
for kv in "${EXTRA_ENV[@]}"; do export "$kv"; done

GAMEDIR="$RUN/prefix/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon"
cp "$ORACLE_BIN/dinput.dll" "$GAMEDIR/"
set +e
( cd "$GAMEDIR" && timeout "$TIMEOUT" wine rct.exe ) >"$RUN/wine.log" 2>&1
RC=$?
set -e
WINEPREFIX="$RUN/prefix" wineserver -k 2>/dev/null || true
WINEPREFIX="$RUN/prefix" wineserver -w 2>/dev/null || true
[[ -n "${ORACLE_KEEP_PREFIX:-}" ]] || rm -rf "$RUN/prefix"
python3 -I "$ROOT/tools/rcttrace.py" summary "$RUN/trace.bin" > "$RUN/summary.txt" 2>&1 || true
if python3 -I "$ROOT/tools/rcttrace.py" finished "$RUN/trace.bin"; then exit 0; fi
echo "oracle run did not reach quit (wine rc=$RC); see $RUN/wine.log and $RUN/hook.log" >&2
exit 1
