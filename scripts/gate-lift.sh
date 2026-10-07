#!/usr/bin/env bash
# The Stage 1 gate (docs/stage1-design.md "Stage 1 gate (acceptance)"): oracle vs lift on every
# corpus case, projection `lift`, coverage cross-check, mutant self-test. See tools/gate_lift.py.
#
#   scripts/gate-lift.sh [--cases GLOB ...] [--oracle-jobs N] [--lift-jobs N] [--out DIR] ...
#
# Report: out/gate-lift/<timestamp>/report.txt and report.json. Exit 0 iff the gate passes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
unset TMPDIR   # Wine's wineserver aborts when TMPDIR is set (scripts/oracle-run.sh)
exec python3 -I "$ROOT/tools/gate_lift.py" "$@"
