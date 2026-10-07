#!/usr/bin/env bash
# Run the lifted rct.exe once on a script (mirrors scripts/oracle-run.sh).
#
#   scripts/lift-run.sh <run-dir> [script] [-- extra lift/run.js args, e.g. --instrument]
#
# Lifts first if the lift is missing, or older than lift/lifter.py when LIFT_REBUILD=1 (not
# automatic: parallel runs would race to rebuild). LIFT_DIR (default out/lift), LIFT_MAP (default:
# the lifter's default map), LIFT_FLAGS (extra lifter flags, e.g. --no-flag-opt --region-bits 0).
# Results in <run-dir>: trace.bin, hook.log, lift-run.json, run.log. Exit status 0 iff the run
# reached the script's quit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$1"; SCRIPT="${2:-}"; shift $(( $# >= 2 ? 2 : 1 ))
[[ "${1:-}" == "--" ]] && shift
LIFT_DIR="${LIFT_DIR:-$ROOT/out/lift}"
NODE="${NODE:-/usr/bin/nodejs}"
TIMEOUT="${LIFT_TIMEOUT:-3600}"

if [[ ! -f "$LIFT_DIR/manifest.json" || ( -n "${LIFT_REBUILD:-}" && "$ROOT/lift/lifter.py" -nt "$LIFT_DIR/manifest.json" ) ]]; then
  "$ROOT/.venv/bin/python" "$ROOT/lift/lifter.py" --exe "$ROOT/game/cd/English/rct.exe" \
    ${LIFT_MAP:+--map "$LIFT_MAP"} ${LIFT_FLAGS:-} --out "$LIFT_DIR" >&2
fi
rm -rf "$RUN"; mkdir -p "$RUN"
[[ -n "$SCRIPT" ]] && cp "$SCRIPT" "$RUN/script.txt"
set +e
timeout "$TIMEOUT" "$NODE" "$ROOT/lift/run.js" --exe "$ROOT/game/cd/English/rct.exe" --lift "$LIFT_DIR" \
  ${SCRIPT:+--script "$RUN/script.txt"} --out "$RUN" "$@" > "$RUN/run.log" 2>&1
RC=$?
set -e
python3 -I "$ROOT/tools/rcttrace.py" summary "$RUN/trace.bin" > "$RUN/summary.txt" 2>&1 || true
if python3 -I "$ROOT/tools/rcttrace.py" finished "$RUN/trace.bin" 2>/dev/null; then exit 0; fi
echo "lift run did not reach quit (rc=$RC); see $RUN/run.log" >&2
exit 1
