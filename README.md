# ECMAmusement Park Tycoon

A testing-driven port of the original RollerCoaster Tycoon (v1.08.183, English, Win32, 13 Jan
2000) from its binary to JavaScript. The binary is the oracle: record what it does, generate
inputs, and diff the port against it. Principles and plan are in `CLAUDE.md`.

Game files are never committed. You supply your own CD image; everything derived from it lives
in `game/` and `out/` (git-ignored).

## Reproducing the oracle (Stage 0)

Host: Ubuntu 24.04 x86-64 with sudo. No Docker.

```
scripts/setup-host.sh                          # apt: wine32 9.0, xvfb, 7z, mingw-w64; .venv for analysis tools
scripts/install-native.sh ~/RCTYCOON.iso       # game/cd + pristine 32-bit prefix game/prefix (about 15 s)
scripts/oracle-run.sh out/runs/try corpus/public/diamond-heights-pause.txt
scripts/gate-determinism.sh                    # the Stage 0 gate (a few minutes); report in out/gate/<time>/
```

`install-native.sh` checks `rct.exe`'s md5 (`59e88bbcf3a6db7ea81c648a4afba935`), maps the CD
as drive D: (type cdrom, label RCTYCOON), copies the files Setup.exe's Full install copies, and
imports the registry keys Setup writes (`install/rct1-install.reg`).

## Layout

```
oracle/      hook DLL (built as dinput.dll): pins, trace, input replay; README documents all of it
scripts/     setup-host.sh, install-native.sh, oracle-run.sh, gate-determinism.sh
tools/       rcttrace.py (read/compare traces), gate_determinism.py, rctdis.py, rctcfg.py (code map),
             coverbisect.py, ptrmask.py, dumpdiff.py
lift/        Stage 1: lifter (lifter.py), runtime, Win32 host, tests (incl. real-CPU differential)
docs/        stage1-scope.md, stage1-design.md, wine-answers.md
corpus/      input scripts: public/ and heldout/ (see corpus/README.md)
install/     registry written by Setup.exe
game/        your CD contents and the pristine prefix (git-ignored)
out/         runs, traces, gate reports, builds (git-ignored)
```

## Stage 0 status

The oracle is pinned (`oracle/README.md` lists every pin and the evidence for it). The gate
runs every corpus case twice as concurrent, independent processes and requires identical game
behaviour: every RNG draw, the RNG state and a full state hash at every tick, and every
command. It also proves it can fail: removing the time pins, flipping an RNG bit, flipping a cash
bit, and dropping a command must each be detected, and no earlier than the point where they were
introduced. The report states the projection, the tolerance and the input distribution, and
lists what a pass does not certify.

Latest result (2026-10-06, `scripts/gate-determinism.sh`): **PASS**. 7 cases (4 public, 3
held-out). Per run pair: 24,216 ticks, 477,705 RNG draws and 24,216 full-state hashes compared,
all bit-identical. Every case's layout-shifted run is identical under the masked projection. All 4
mutants were detected at their injection point.

## Stage 1: the mechanical lift (accepted 2026-10-07)

`lift/` translates every block of rct.exe (static code map v4: 92,055 blocks, 392k instructions,
`.text` + CODESEG + CodeSeg) into JavaScript and runs it in Node 18 under a JS host that
reproduces the oracle's pinned Win32 environment (`docs/stage1-design.md`). Generated code is
derived from your rct.exe and stays in `out/lift/`.

```
.venv/bin/python lift/lifter.py                       # -> out/lift (and --no-flag-opt --out out/lift-ref)
scripts/lift-run.sh out/lruns/x corpus/public/title.txt
scripts/gate-lift.sh                                  # the Stage 1 gate -> out/gate-lift/<time>/report.txt
```

Gate result (oracle build `bb64337544163fd0`, lift host build `ea43519843d9c364`): **PASS**.

| Stage | Result |
|---|---|
| trace | 43/43 cases identical to the oracle on projection `lift` (rng + masked state + commands + input). 364,240 ticks, 6.75M RNG draws, 364k masked state hashes, 5,367 commands. OS-side records identical in all 43; raw state hash identical in 41. |
| coverage | 43/43: the lift executed exactly the blocks the binary executed |
| register | 86/86 sampled tick windows identical instruction by instruction (59.8M block entries, 535M register comparisons, 36.4M written bytes) |
| self-test | 4/4 trace mutants and 2/2 register mutants detected |

What this does **not** certify:
- 18.7% of lifted instructions are executed by no corpus case. They are lifted and checked
  instruction-by-instruction on the real CPU (`lift/test/cpu`), but not in context.
- Flag or register faults outside the sampled windows are caught only if they reach compared
  state (the trace stage is blind to some; measured in the gate report).
- Paths the corpus never takes: fullscreen DirectDraw, saved games, sound, multi-tick frames.
- Environments other than this one: Wine 9.0 build, Xvfb 1024×768×24, this CPU's `cpuid` and
  `GetSystemInfo`.

Speed: the lift takes 1.6–4.4× the oracle's wall time per case.

### Decisions awaiting review (principle 8)
1. Corpus: loading scenarios the UI locks (5–20), building ride types not yet researched, scripted
   UI clicks at fixed coordinates, and the cases left out (multi-tick frames, saved games, 7 of
   49 commands). Details: `corpus/README.md`.
2. New pins added during Stage 1: fixed register values after every OS call, deterministic file
   search handles, scripted file dialogs (`oracle/README.md`).
3. The host reproduces Wine's addresses (heap, DIB, CSG1 mapping, file handles) and the oracle's
   stack depth for injected calls, so raw state matches too. The gate itself relies only on the
   masked projection.
4. Standard input is not pinned: its file type depends on how the oracle is launched. It reaches
   only C-runtime data; proposal: launch with `</dev/null`.

## Stage 1 scoping

`docs/stage1-scope.md` has the measurements (code map, instruction set, self-modifying code,
OS-derived state, memory model, OS surface, work per tick, corpus coverage), the decisions
proposed for review, and a work order.

### Decisions proposed for human review (principle 8)

These were chosen to make the gate meaningful. Execution cannot judge them.

1. **Projection.** Exact comparison of DATASEG + DataSeg at every tick, plus every RNG draw and
   every command. `.data` (C runtime and glue) and the framebuffer are excluded in Stage 0.
2. **CD alias.** The game's CD check needs `~` at index 5 of the 8.3 alias of
   `D:\Saved Games`. The oracle reports `SAVED~1`, assuming the genuine disc passed under the
   period OS. Wine's own alias fails the check, and then every new game quits to the title.
3. **Pacing.** One virtual millisecond per time query gives exactly one logic tick per frame.
   The real game runs 1–4 ticks per frame depending on frame time. Multi-tick frames (input
   applied between groups of ticks) are therefore not exercised. `RCTHOOK_QUANTUM` changes this.
4. **Corpus.** The five scenarios unlocked at first start, a few hundred to a few thousand
   ticks each, with park-open, hire-staff and pause commands. Which cases are held out:
   `corpus/heldout/`.
5. **Idle cursor.** It sits at screen (1000,740), outside the 640×480 game area, unless a script
   moves it.

## Binary facts

- `rct.exe` md5 `59e88bbcf3a6db7ea81c648a4afba935`. Other language builds differ; English is pinned.
- No SafeDisc/SecuROM. The CD key in the registry is 0 and still accepted. There is an in-game
  CD check (`0x42F1D3`, see `oracle/README.md`).
- `CODESEG` 0x41C000, 1.88 MB of hand-written asm. `.text` 107 KB of C runtime/OS glue.
- `DATASEG` 0x5F4000–0x9A161C (3.8 MB) of static game state at fixed addresses.
- `CodeSeg` 0x9B3000 (38 KB) is code in a writable section, likely self-modifying blitters.
- DirectDraw is loaded dynamically (`DDRAW.DLL` via LoadLibrary); other imports include DINPUT,
  DSOUND, WINMM, DPLAYX.
- The game has its own input recorder/player (`[0x99C16B]`: 1 play back, 2 record), used by the
  tutorial.
