#!/usr/bin/env bash
# Screenshot the oracle's virtual display to out/<name>.png
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; mkdir -p "$ROOT/out"
docker exec "${ORACLE_NAME:-rct1-oracle}" import -window root "/work/out/${1:-shot}.png"
