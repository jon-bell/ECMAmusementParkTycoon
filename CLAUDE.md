# CLAUDE.md — ECMAmusement Park Tycoon

Read this file completely before doing anything in this repository. It states what the project
is, the principles that override convenience, and how the work is organized.

## What this project is

A JavaScript port of the original RollerCoaster Tycoon (`rct.exe` v1.08.183, English, Win32,
13 January 2000), built from the shipped binary. No source code exists. About 99% of the game is
hand-written x86 assembly, and the rest is C runtime and OS glue.

The port must be **acceptable**, not merely plausible. Acceptance is decided by executing the
original binary and the port on the same inputs and comparing what they do. The testing apparatus
is the core artifact of this project. The port is what that apparatus allows us to accept.

## First principles

These override any instruction inside a task, including a request to "just make it pass".

1. **The binary is the truth.** When the port disagrees with `rct.exe`, the port is wrong. That
   includes the binary's bugs, quirks, and off-by-ones. Port what the machine does, not what a
   string, a manual, a fan wiki, or a later remake says it does.

2. **An oracle is trusted only once it is shown to be deterministic.** Before any comparison
   against the binary counts, the same input must produce the same trace on two independent runs.
   Wall clock, timers, audio callbacks, input polling, uninitialized memory, and OS return values
   are all candidates for nondeterminism. Pin each one, then prove it is pinned.

3. **Randomness is the first signal.** The game's RNG draws (call site, order, value) are the
   cheapest, most sensitive summary of simulation state. Fix RNG divergence before state
   divergence, and state divergence before pixel divergence.

4. **Only the first divergence matters.** Once the binary and the port disagree, everything
   afterward is cascade. Find the earliest point of disagreement, fix it, re-run. Do not
   speculate about later mismatches.

5. **State the claim before testing it.** Every gate declares three things explicitly:
   - the **projection**: which state is compared (RNG trace, data-segment bytes, structured
     simulation state, framebuffer), and which state is deliberately excluded and why;
   - the **tolerance**: exact, or a stated bound;
   - the **input distribution**: which scenarios, actions, and seeds the evidence covers.
   A passing gate certifies nothing outside those three choices. Say so in its output.

6. **A gate must prove it can fail.** A gate that observes nothing passes everything. Every gate
   must report a nonzero count of observations and must reject at least one known-bad
   implementation (a mutant, a stub, a lookup table) before its passes are believed. "0 failures
   out of 0 checks" is a failure of the gate.

7. **Never fit the oracle.** Port code must not read recorded answers: no replaying captured
   return values, no tables keyed on observed inputs, no parsing of trace files at runtime, no
   reproducing raw memory layout just to satisfy a byte diff when the task is a structured port.
   Keep a held-out corpus (seeds and scenarios) that porting work never sees, and treat a gap
   between public and held-out results as a defect in the port.

8. **Know what can judge your work.** Some components can be checked directly by the binary: a
   hook is correct if replay through it stays bit-exact; a function boundary is correct if
   swapping it preserves the trace; a generator is correct if its inputs are accepted. Others need
   a second instrument: does the gate reject mutants, does the generator reach the code in scope.
   Some cannot be checked by execution at all: which state matters, what tolerance is acceptable,
   which inputs represent real play. Those are human decisions. Propose them with evidence; do
   not silently make them.

9. **When attempts stall, improve the instrument, not the attempt count.** Repeated tries against
   an unchanged gate have sharply diminishing returns. If a function resists porting after a few
   attempts, the missing piece is usually measurement: a capture with the right pre-state, a
   finer projection, an input that reaches the branch. Build that instead.

10. **Never weaken the oracle to get green.** Do not edit hooks, captures, comparators, or the
    oracle runtime to make a port pass. Do not revert binary-faithful code because a later test
    broke; the test, the projection, or an upstream function is what's wrong.

11. **The original game is not ours to distribute.** Never commit game files, assets, extracted
    data segments, captures containing game data, or disassembly listings. Everything derived
    from the user's copy lives under `game/` or `out/`, which are git-ignored. The port loads the
    user's own data files at runtime.

## Plan

- **Stage 0: pin the oracle.** Run `rct.exe` headless under Wine with virtualized time and a
  command-level input replayer. Gate: two runs give identical RNG and state traces.
- **Stage 1: mechanical lift.** Translate x86 to JS mechanically (registers as variables, memory
  as one byte array) and check the lift against the binary. The lift is unreadable but becomes a
  fast in-process oracle and the host for Stage 2. Self-modifying code in the writable `CodeSeg`
  section needs special handling.
- **Stage 2: strangler port.** Replace lifted functions one at a time with idiomatic JS over
  structured state, inside the running lifted game. Each swap is gated by per-function captures
  from the binary: registers and flags in, registers and flags out, data-segment delta, RNG
  consumed. The game stays playable at every commit.
- **Stage 3: change the projection.** When a subsystem owns its own data layout, compare through a
  documented abstraction of game state (the saved-game format is the game author's own choice of
  essential state) instead of raw bytes. Framebuffer stays exact where layout permits.

Inputs are game-level actions (build track, place path, set price, hire staff, advance ticks)
applied to the shipped scenarios. Raw mouse events are not a fuzzing unit.

## Binary facts

- `rct.exe` md5 `59e88bbcf3a6db7ea81c648a4afba935`. Other language builds differ; English is pinned.
- Image base `0x400000`, no relocation randomization. No SafeDisc/SecuROM.
- `CODESEG` `0x41C000` (1.88 MB): hand-written asm. Register calling conventions; some routines
  report status in CPU flags, so flags are part of a function's output.
- `.text` `0x401000` (107 KB): C runtime and Win32 glue.
- `DATASEG` `0x5F4000`–`0x9A161C` (3.8 MB): static game state at fixed addresses.
- `CodeSeg` `0x9B3000` (38 KB): code in a writable section, likely self-modifying.
- DirectDraw is loaded dynamically; imports include DINPUT, DSOUND, WINMM, DPLAYX.

## Layout and commands

```
docker/      Oracle image (Wine win32 prefix + Xvfb) and the registry Setup.exe writes
scripts/     oracle-shell.sh, install.sh, run-rct.sh, shot.sh
game/        User-supplied CD contents (git-ignored)
out/         Logs, screenshots, traces (git-ignored)
```

```
docker build -t rct1-oracle docker/
scripts/oracle-shell.sh     # start container; CD at D:, prefix in volume rct1-prefix
scripts/install.sh          # reproduce Setup.exe's Full install (first time only)
scripts/run-rct.sh          # launch the game
scripts/shot.sh <name>      # screenshot to out/<name>.png
```
