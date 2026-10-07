#!/usr/bin/env bash
# Build the native harness (out/cpu/harness.exe) and its Wine prefix (out/cpu/prefix).
#
# The harness must own the address range of rct.exe's image (0x400000-0x9C4000): Wine maps NLS
# tables and heaps into low memory before main() runs. So the harness is linked at 0x400000
# with an uninitialised, executable section `.rctimg` spanning 0x401000-0x9C4000 (rct.exe's
# sections), and its own code after it. The linker script is the toolchain's default with
# that one change, generated at build time.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/out/cpu"
mkdir -p "$OUT"
i686-w64-mingw32-ld --verbose | sed -n '/^=======/,/^=======/p' | sed '1d;$d' |
  sed 's|^  \.text  __image_base__ + ( __section_alignment__ < 0x1000 ? \. : __section_alignment__ ) :|  .rctimg __image_base__ + 0x1000 : { *(.rctimg) }\n  .text ALIGN(__section_alignment__) :|' \
  > "$OUT/harness.ld"
grep -q '^  .rctimg' "$OUT/harness.ld" || { echo "linker script edit failed" >&2; exit 1; }
i686-w64-mingw32-gcc -O1 -Wall -o "$OUT/harness.exe" "$ROOT/lift/test/cpu/harness.c" \
  -Wl,--image-base,0x400000 -Wl,-T,"$OUT/harness.ld" -Wl,--disable-dynamicbase -static-libgcc
if [[ ! -f "$OUT/prefix/system.reg" ]]; then
  unset TMPDIR
  WINEPREFIX="$OUT/prefix" WINEARCH=win32 WINEDEBUG=-all wineboot -i >/dev/null 2>&1
fi
echo "built $OUT/harness.exe"
