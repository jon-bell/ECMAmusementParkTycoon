#!/usr/bin/env bash
# Run wineprobe.exe in the oracle's environment (same as scripts/oracle-run.sh: fresh copy of the
# pristine prefix, private 1024x768x24 Xvfb, started from the game directory, stdout and stderr
# redirected to a file) and write its answers to <out>.
#   lift/test/host/probe/run-probe.sh <wineprobe.exe> <out.txt>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
EXE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; OUT="$2"
unset TMPDIR
RUN="$(mktemp -d "$ROOT/out/host/probe-run.XXXXXX")"
mkdir -p "$RUN/prefix"
tar -C "$ROOT/game/prefix" --exclude=./drive_c/windows -cf - . | tar -C "$RUN/prefix" -xf -
cp -al "$ROOT/game/prefix/drive_c/windows" "$RUN/prefix/drive_c/windows"
exec {DFD}<> <(:)
Xvfb -displayfd "$DFD" -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 & XPID=$!
read -r -t 20 -u "$DFD" DISP
cleanup() { WINEPREFIX="$RUN/prefix" wineserver -k 2>/dev/null || true; kill "$XPID" 2>/dev/null || true; rm -rf "$RUN"; }
trap cleanup EXIT
export DISPLAY=":$DISP" WINEARCH=win32 WINEPREFIX="$RUN/prefix" WINEDEBUG="err+all,fixme-all"
export WINEDLLOVERRIDES="winemenubuilder.exe=d"
GAMEDIR="$RUN/prefix/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon"
cp "$EXE" "$GAMEDIR/"
( cd "$GAMEDIR" && timeout 120 wine "$(basename "$EXE")" ) > "$OUT" 2> "$OUT.stderr"
WINEPREFIX="$RUN/prefix" wineserver -w 2>/dev/null || true
