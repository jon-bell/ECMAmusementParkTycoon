#!/usr/bin/env bash
# Start a persistent oracle container: Wine prefix + Xvfb, CD mounted as D: (cdrom, label RCTYCOON).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/out"
NAME="${ORACLE_NAME:-rct1-oracle}"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -v "$ROOT:/work" -v rct1-prefix:/home/rct/.wine rct1-oracle bash -c '
  rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
  Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 &
  sleep 1
  ln -sfn /work/game/cd "$WINEPREFIX/dosdevices/d:"
  wine reg add "HKLM\\Software\\Wine\\Drives" /v d: /d cdrom /f >/dev/null 2>&1
  echo RCTYCOON > /work/game/cd/.windows-label 2>/dev/null || true
  sleep infinity' >/dev/null
echo "$NAME up"
