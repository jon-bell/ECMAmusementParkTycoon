#!/usr/bin/env bash
# Build the pristine oracle prefix in game/prefix from the user's CD image.
#
#   scripts/install-native.sh [path/to/RCTYCOON.iso]
#
# 1. extracts the CD to game/cd (skipped if present) and checks rct.exe's md5;
# 2. creates a 32-bit Wine prefix (game/prefix) with the CD mapped as drive D: (type cdrom,
#    label RCTYCOON);
# 3. reproduces the Full install that Setup.exe performs: game files under
#    C:\Program Files\Hasbro Interactive\RollerCoaster Tycoon and the registry keys in
#    install/rct1-install.reg (CD key 0 is accepted).
# Every oracle run starts from a fresh copy of game/prefix and never modifies it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ISO="${1:-$HOME/RCTYCOON.iso}"
MD5=59e88bbcf3a6db7ea81c648a4afba935
unset TMPDIR   # Ubuntu's Wine 9.0 wineserver aborts ("free(): invalid pointer") when TMPDIR is set

if [[ ! -f "$ROOT/game/cd/English/rct.exe" ]]; then
  [[ -f "$ISO" ]] || { echo "CD image not found: $ISO" >&2; exit 2; }
  mkdir -p "$ROOT/game/cd"
  7z x -y -o"$ROOT/game/cd" "$ISO" >/dev/null
fi
got=$(md5sum "$ROOT/game/cd/English/rct.exe" | cut -d' ' -f1)
[[ "$got" == "$MD5" ]] || { echo "rct.exe md5 $got, expected $MD5 (English 1.08.183)" >&2; exit 3; }
echo RCTYCOON > "$ROOT/game/cd/.windows-label"   # volume label Wine reports for D:

PFX="$ROOT/game/prefix"
rm -rf "$PFX"
Xvfb -displayfd 3 -screen 0 1024x768x24 -nolisten tcp 3>"$ROOT/game/.xdisplay" >/dev/null 2>&1 & XPID=$!
trap 'kill $XPID 2>/dev/null || true' EXIT
for _ in $(seq 100); do [[ -s "$ROOT/game/.xdisplay" ]] && break; sleep 0.1; done
export DISPLAY=":$(cat "$ROOT/game/.xdisplay")" WINEARCH=win32 WINEPREFIX="$PFX" WINEDEBUG=-all
export WINEDLLOVERRIDES="winemenubuilder.exe=d"
wineboot -i
wineserver -w

GAMEDIR="$PFX/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon"
mkdir -p "$GAMEDIR"
cp -r "$ROOT/game/cd/Data" "$ROOT/game/cd/Scenarios" "$ROOT/game/cd/Tracks" "$ROOT/game/cd/Saved Games" "$GAMEDIR/"
cp "$ROOT/game/cd/English/rct.exe" "$ROOT/game/cd/English/readme.txt" "$GAMEDIR/"
chmod -R u+w "$GAMEDIR"
wine regedit "$ROOT/install/rct1-install.reg"
ln -sfn "$ROOT/game/cd" "$PFX/dosdevices/d:"
wine reg add 'HKLM\Software\Wine\Drives' /v d: /d cdrom /f >/dev/null
wineserver -w
rm -f "$ROOT/game/.xdisplay"
# Runs hard-link drive_c/windows from this prefix (scripts/oracle-run.sh); read-only files make an
# in-place write through a link fail instead of altering the pristine prefix.
find "$PFX/drive_c/windows" -type f -exec chmod a-w {} +
md5sum "$GAMEDIR/rct.exe"
echo "pristine prefix ready: $PFX"
