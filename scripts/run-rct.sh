#!/usr/bin/env bash
# Launch rct.exe in the oracle container; log to out/rct.log
docker exec -d "${ORACLE_NAME:-rct1-oracle}" bash -c 'cd "$WINEPREFIX/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon" && WINEDEBUG=err+all wine rct.exe > /work/out/rct.log 2>&1'
