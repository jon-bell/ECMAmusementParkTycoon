#!/usr/bin/env bash
# Install the oracle's host dependencies (Ubuntu 24.04 "noble", x86-64). Needs sudo.
#
# Versions this project was validated with (recorded by the gate in every report):
#   wine 9.0~repack-4build3 (Ubuntu noble/universe), xvfb from noble, mingw-w64 11.0.1.
set -euo pipefail
sudo dpkg --add-architecture i386
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  wine wine32:i386 wine64 libwine:i386 \
  xvfb xauth x11-utils xdotool imagemagick \
  p7zip-full \
  gcc-mingw-w64-i686 binutils-mingw-w64-i686 make \
  python3 python3-venv \
  nodejs
# Analysis tools (disassembly helpers in tools/rctdis.py); kept out of the system Python.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -q capstone pefile
wine --version
nodejs --version   # the lift (Stage 1) runs on Ubuntu's Node 18
