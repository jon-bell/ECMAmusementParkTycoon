# ECMAmusement Park Tycoon

A testing-driven port of the original RollerCoaster Tycoon (v1.08.183, English, Win32, 13 Jan 2000)
from its binary to JavaScript. The binary is the oracle: record its behavior, generate inputs,
and diff the port against it. Principles and plan are in `CLAUDE.md`.

Game files are never committed. Put the CD contents in `game/cd/` (`7z x -ogame/cd RCTYCOON.iso`).

## Stage 0: oracle runtime (done so far)
- `docker build -t rct1-oracle docker/` builds Wine (win32 prefix) + Xvfb.
- `scripts/oracle-shell.sh` starts a container with the CD mapped as `D:` (cdrom).
- `scripts/install.sh` reproduces Setup.exe's Full install (no CD streaming during play) into the
  persistent `rct1-prefix` volume. `docker/rct1-install.reg` is the registry Setup writes.
- `scripts/run-rct.sh` launches the game; it boots to the title screen headless.
- `scripts/shot.sh <name>` screenshots the virtual display to `out/`.

## Binary facts
- `rct.exe` md5 `59e88bbcf3a6db7ea81c648a4afba935`. Other language builds differ; English is pinned.
- No SafeDisc/SecuROM. The CD key in the registry is 0 and still accepted.
- `CODESEG` 0x41C000, 1.88 MB of hand-written asm. `.text` 107 KB of C runtime/OS glue.
- `DATASEG` 0x5F4000–0x9A161C (3.8 MB) of static game state at fixed addresses.
- `CodeSeg` 0x9B3000 (38 KB) is code in a writable section, likely self-modifying blitters.
- DirectDraw is loaded dynamically (`DDRAW.DLL` via LoadLibrary); other imports include DINPUT, DSOUND, WINMM, DPLAYX.

## Next
1. Hook DLL (mingw) for the RNG and the game tick; virtualize GetTickCount/timeGetTime.
2. Two-run determinism gate on the title-screen demo and on one scenario.
