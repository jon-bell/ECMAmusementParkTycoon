#!/usr/bin/env bash
# Stage 0 gate: two (or --runs N) independent oracle runs per corpus case must produce identical
# traces, and known-bad oracles must be detected. Report in out/gate/<timestamp>/report.txt.
#   scripts/gate-determinism.sh [--runs N] [--jobs J] [--cases 'public/*' ...] [--no-mutants]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
unset TMPDIR
exec python3 -I "$ROOT/tools/gate_determinism.py" "$@"
