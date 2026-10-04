#!/usr/bin/env bash
# Reproduce the Full install that Setup.exe performs, into the persistent prefix volume.
set -euo pipefail
docker exec "${ORACLE_NAME:-rct1-oracle}" bash -c '
  D="$WINEPREFIX/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon"
  mkdir -p "$D"
  cp -r /work/game/cd/Data /work/game/cd/Scenarios /work/game/cd/Tracks "/work/game/cd/Saved Games" "$D/"
  cp /work/game/cd/English/rct.exe /work/game/cd/English/readme.txt "$D/"
  chmod -R u+w "$D"
  wine regedit /work/docker/rct1-install.reg
  wineserver -w
  md5sum "$D/rct.exe"'
