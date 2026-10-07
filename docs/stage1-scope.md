# Stage 1 scope: mechanical lift of rct.exe to JavaScript

Stage 1 (CLAUDE.md): translate the x86 mechanically into JS (registers as variables, memory as
one byte array), check the lift against the binary, and use it as a fast in-process oracle and
as the host for Stage 2. This document records the spikes run to scope that work: what was
measured, how, what it implies, and which decisions are left to a human (principle 8). Every
number is reproducible with the tools listed at the end. Raw outputs are under `out/spikes/`
(git-ignored: they derive from the user's copy of the game).

## Summary

| Question | Answer | Evidence |
|---|---|---|
| How much code? | 388k instructions, 90.5k basic blocks, 1,170 call targets. CODESEG 95% and CodeSeg 99% accounted for as code or embedded tables. | static map v2, validated dynamically (M1) |
| Which instructions? | Integer only in game code (x87 only in 15 C-runtime instructions). 98 mnemonics. 43% carry the 16-bit prefix; high-byte registers are common. | M2 |
| Self-modifying code? | **None observed.** No writes to `.text`, CODESEG or CodeSeg over the whole corpus. No static evidence of any. | M3 |
| Does code read code? | **Yes.** A startup checksum over `0x42EAE0–0x431510` lands in compared state (`0x6E2B76`), and ~10.5k jump tables plus a few data tables sit inside CODESEG. | M4 |
| OS values in game state? | Exactly 38,373 dwords: pointers into Wine-allocated or mapped memory, plus one file handle. A masked projection excludes them and still catches state mutants. | M5 |
| Memory the game uses outside its image | One read-only file mapping (CSG1.DAT, 22.6 MiB), the screen DIB (768 KiB), 9 heap blocks, 2 VirtualAlloc regions. | M6 |
| OS surface | 104 OS/COM functions called; game code calls 59 C-runtime/glue functions and shares 41 `.data` variables with them. | M7 |
| Work per tick | 210k (quiet park) to 1.2M (busy park) game instructions per tick, rendering included. | M8 |
| What the corpus exercises | **12.5% of CODESEG instructions**, 42% of functions, 3 of 49 game commands. | M9 |

**Main risk:** the evidence base, not the lift. A lift can be complete (static map, no
self-modifying code, integer-only, narrow OS surface) yet be checked against only an eighth of
the game code. Growing the corpus is Stage 1 work, not later work.

## Measurements

### M1. Code size and shape (static map, dynamically validated)

`tools/rctcfg.py` disassembles by recursive descent: entry, the 49-entry `game_do_command`
table (`0x5F49A0`), immediates and data dwords that point at code, pointer tables embedded in
code, and 13.6k instruction addresses observed executing (single-step, M8). Heuristic seeds are
gated: clean decode, no overlap with any other decoded instruction, and not 64 KiB-aligned unless
also a direct branch target.

- 388,245 instructions; 90,481 blocks; 35,890 of them trusted (reached without heuristic seeds).
- 10.5k jump/call tables embedded in CODESEG right after `jmp [reg*4+table]`. Most game code
  (unrolled painting and track routines) is reachable only through them.
- 334 unresolved indirect transfers, dominated by window/object event dispatch
  (`call [esi+4]`, `call [esi]`).
- Control flow that is not call/return: 5 long-jumps back to the main loop
  (`mov esp,[0x991F6C]; jmp 0x438A1D`), SEH-style stack restores in the C runtime, and event
  handlers dispatched through struct fields.
- **Dynamic validation:** a one-shot `int3` at every block start, over the whole corpus,
  reproduces every reference RNG trace exactly (M9).
  - Map v1 failed this test. Six blocks came from data dwords such as `0x005E0000` mistaken for
    code pointers; the game reads those bytes as data, or executes them as part of a real
    instruction the map had missed.
  - v1 had also missed 1,028 instruction addresses that the game executes.
  - Both defects were fixed in v2. The breakpoint test is now the acceptance test for any code
    map.

### M2. Instruction set

- 98 mnemonics.
- No x87, MMX or SSE in CODESEG/CodeSeg; 15 x87 instructions in the C runtime (`.text`).
- No privileged instructions, segment loads or `lock`; `cpuid` once in `.text`.
- 43% of CODESEG instructions carry the 0x66 operand-size prefix, and 10.7% use 8-bit
  registers (13.5k of them `ah`/`bh`/`ch`/`dh`). Flags at 8- and 16-bit width are core semantics.
- **Flags are function outputs:** 474 call sites, across 65 callees, branch on or `adc` with
  flags left by the callee. There are 107 `stc; ret` and 5 `clc; ret` exits.
- `rep movs/stos/scas` and `std` (backwards string ops) appear in the C runtime and in
  CodeSeg blitters.

### M3. Self-modifying code: none

- `RCTHOOK_SPIKE=codewatch` compares `.text`, CODESEG and CodeSeg with their previous contents
  every frame. Over all 7 corpus cases it found 0 changed bytes.
- The detector is proven sensitive: a 1-byte poke into CodeSeg was reported at the right frame
  and tick.
- Statically, no instruction writes an absolute address inside a code section.

So the lift can be ahead-of-time translation, with no need to handle self-modification. The
writable CodeSeg section is just blitter code in a writable section.

### M4. Code read as data

- `0x5DF3BB`, called once from the first frame's initialisation (`0x43862A`), XOR-rotates the
  bytes in `0x42EAE0–0x430931` and `0x430934–0x431510`. It addresses them through obfuscated
  offsets (`cs:[esi-0x23F40A]`) and stores the result at `0x6E2B76`, inside the compared state.
- This is a tamper check. Breakpoints in that range made the game misbehave until they were
  armed only after the first frame.
- Jump tables and some data tables live inside CODESEG and are read with ordinary loads.

The lift's memory image must contain the original code bytes, read-only, at their original
addresses. Translated code lives beside the image, not in place of it.

### M5. OS-derived values in game state, and a masked projection

Method: `RCTHOOK_SPIKE=heapshift=N` leaks heap, global and virtual memory and 7 OS handles
before the game starts, which shifts everything the OS hands out. Each corpus case is run at
base and at shifted layout, and state dumps are diffed:

- Every case gives the **same 38,356 differing dwords at the final tick, and all RNG traces are
  identical**. The OS values steer nothing.
- One more dword (`0x9A200C`) differs only at tick 1.

The OS-derived dwords:

| Address | What |
|---|---|
| `0x8DC0B4 + 16·i`, i < 38,365 | sprite table (from CSG1I.DAT), pointer into the CSG1.DAT mapping |
| `0x5F96C0`, `0x5F96D0` | pointers into the screen DIB |
| `0x99FB7C`, `0x99FB8C` | screen drawing context: DIB bits |
| `0x9A2008`, `0x9A200C`, `0x9A2010` | CSG1.DAT mapping base; a transient OS address |
| `0x5F88A4` | handle of the last scenario file opened |

`TR_MSTATE` (projection `masked` in `tools/rcttrace.py`) hashes the state with these dwords
read as 0. It is validated three ways:

- shifted layout vs base: identical over 300 ticks of Diamond Heights;
- single-stepping instrument vs base: identical;
- the cash bit-flip mutant: detected one tick after the flip.

The Stage 0 gate now runs a layout-shifted copy of every case and requires `masked` to match.
It passes on all 7 cases.

#### M5 addendum (Stage 1, ORACLE INSTRUMENTS): the mask audited, `oracle/mask.h`

The gate's layout-shift run of `heldout/tour-sc17-lightning-peaks` diverged on `masked` at tick
10647 with identical RNG: the bits pointer of a second drawing context (`0x9A012C`) was not
masked. The tick-1 dumps used above could not see it, because the game fills that context only
when zooming. The mask was therefore re-derived, dynamically at every tick and statically.

- **Single source of truth.** `oracle/mask.h` lists the masked state, one `MASK_DWORD(addr)` or
  `MASK_STRIDE(base, stride, count)` per line. `rcthook.c` includes it and the JS host parses it.
  Masking is per byte: a masked byte reads as 0 inside its 32-bit hashed word. For the previous
  (aligned) entries this gives the same hash values as before.
- **Dynamic, phase 1** (`RCTHOOK_SPIKE=ptrscan`). Every tick, every state dword at every 2-byte
  offset is checked (only changed words after the first tick). One whose value lies in OS memory
  (mapped view, private allocation, another module's image, stack) is recorded. Runs: all 43 corpus
  cases plus 18 UI/zoom/window/tour discovery scripts of the CORPUS workstream (`out/cw/scripts`),
  each clean and with `heapshift=200003`: 122 runs. Union: 189,651 candidate addresses, most of
  them game data that looks like a pointer by coincidence.
- **Dynamic, phase 2** (`RCTHOOK_SPIKE=watch=LIST`). The same 61 scripts, clean and shifted, log
  every change of every candidate at every tick. The game is deterministic and the RNG agrees, so
  coincidental values have identical logs. A byte is layout-dependent iff its value differs between
  the clean and the shifted log at the same logged change. `tools/watchdiff.c` also checks that the
  two logs have the same (tick, address) sequence.
  - Result (`tools/maskaudit.py diff`): 54,313 layout-dependent bytes in 38,360 ranges. 38,349
    ranges are sprite-table entries; the other 11 are listed below. With the new entries, **0 bytes
    are uncovered** by `mask.h`.
- **Static.** Drawing contexts (bits pointer, then x, y, w, h, pitch, zoom as words) are passed to
  the drawing routines in `edi`. Of the 59 DATASEG addresses the code loads into `edi` as an
  immediate, exactly six are drawing contexts that hold DIB pointers at run time: `0x5F96C0`
  (written directly), `0x5F96D0`, `0x99FB7C`, `0x99FB8C`, `0x99FE08` and `0x9A012C`. Every other
  route from OS memory into game code goes through the glue in `.text`:
  - the CSG1.DAT view comes only from the `MapViewOfFile` wrapper `0x4080E0` (sprite table,
    `0x9A2008`–`0x9A2010`);
  - game code calls `malloc` only through `0x404656`, whose single caller stores the result at
    `0x628C44` (a 64 KiB buffer used by the map window).
- **Handles** do not move under the original heapshift (it shifted kernel handles only).
  `RCTHOOK_PERTURB=LoadCursorA:ret^2` (an API-trace experiment) changed the masked state from
  tick 1. A dump diff placed the change in a table of 22 `HCURSOR`s at `0x9A1550`. `heapshift` now
  also creates 3 windows, 5 cursors, 10 GDI objects and a DC before the game starts. A tick-5 dump
  then differs from a clean one, outside the mask, only in that table. Since then the gate's
  layout-shift runs check USER and GDI handles too.

New entries: `0x9A012C`, `0x99FE08` (drawing-context bits), `0x628C44` (malloc'd buffer) and
`0x9A1550 + 4·i`, i < 22 (cursor handles). The full list with the code addresses is `mask.h`.

**Not covered:** pointers into OS memory that the corpus never produces at any tick, in code
paths it never runs. The static argument above covers the drawing contexts and the malloc route;
it does not cover a pointer computed some other way.

### M6. Memory model

From `RCTHOOK_SPIKE=memmap` plus the API counts. Outside the image (`0x400000–0x9BD000`) the
game uses:

- a read-only file mapping of CSG1.DAT at `0x03C80000` (22.6 MiB; sprite pointers point into it);
- the screen DIB section, 1024×768×8 at `0x019A0000`, of which the game area is 640×480;
- 9 `HeapAlloc` blocks and 2 `VirtualAlloc` regions;
- its stack.

A sparse page map covering these is all the lift needs.

### M7. OS surface and the glue boundary

- **104 distinct OS/COM functions** are called across the corpus (of 234 imported), per
  `RCTHOOK_SPIKE=apicount`:

  | DLL | Functions |
  |---|---|
  | KERNEL32 | 46 + 1 by name |
  | USER32 | 28 |
  | GDI32 | 14 |
  | WINMM | 6 |
  | ADVAPI32 | 4 |
  | DSOUND | 2 |
  | DDRAW | 1 |
  | DINPUT | 1 |
  | IDirectDraw | 1 method |

  Run totals for a busy 3,000-tick case include 107k `timeGetTime`, 14.5k `ReadFile` and
  3.9k `StretchDIBits` calls.
- **Rendering.** Under Xvfb the game takes its windowed GDI path (`CreateDIBSection`,
  `StretchDIBits`, palette animation). DirectDraw is used only for `EnumDisplayModes`, so the
  fullscreen DirectDraw path is not exercised.
- **Unpinned OS answers that steer the game.** These are stable in this environment, but a JS
  host must reproduce them, so they need recording:
  - `EnumDisplayModes`, which selects the windowed path;
  - `GetSystemMetrics`, `GetDeviceCaps`, `SystemParametersInfoA`;
  - `GetVersion(Ex)`, `GetSystemInfo`, `GetKeyboardType`;
  - `mciSendStringA` and `midiOut*` (music);
  - `GetCPInfo`/`LCMapStringW` (C runtime);
  - the registry reads.
- **The `.text` boundary.**
  - Game code (CODESEG/CodeSeg) never calls the OS directly. It calls 59 `.text` functions
    from 264 sites.
  - `.text` calls into game code at exactly one site: the main loop's call of the frame
    function, `0x4010F7` → `0x4385D8`. The window procedure (`0x403D79`) and the message pump
    are `.text` too.
  - Game code reads 41 `.data` variables (and writes 10 of them) that the glue maintains:
    keyboard and mouse state, cursor position, date fields, the app-active flag, frame flags.

### M8. Work per tick and the cost of instrumentation

- `RCTHOOK_SPIKE=istep=A:B` single-steps every game instruction, by setting the trap flag in
  the tick hook and resuming stepping after OS calls with a breakpoint at the return address.
  - Busy park (Diamond Heights, 555 guests): 1.11–1.27M instructions per tick.
  - Quiet park (Forest Frontiers): 211–214k.
  - Both include drawing the frame, since one tick runs per frame.
  - About 7 µs per stepped instruction, so stepping suits short windows only.
- Stepping does not perturb the game: identical RNG trace and masked state.
- It yields an exact executed-instruction bitmap. Every executed address must be an
  instruction start in the code map; this check found v1's 1,028 missing addresses.
- The oracle runs about 200 ticks/s with full-state hashing. A JS lift that matches it needs
  roughly 50–250M emulated instructions/s.

### M9. What the corpus exercises

One-shot breakpoints on all 90,481 v2 blocks, over all 7 corpus cases. Every RNG trace is
identical to the gate's reference, so the instrument does not perturb the game.

| Section | Blocks executed | Instructions executed |
|---|---|---|
| CODESEG | 18,768 / 81,418 (23.1%) | 44,620 / 355,770 (12.5%) |
| CodeSeg | 1,084 / 3,318 (32.7%) | 1,598 / 9,287 (17.2%) |
| `.text` | 1,764 / 5,745 (30.7%) | 5,233 / 23,188 (22.6%) |

- Functions entered: 494 of 1,170 (42%). Game commands executed: 3 of 49 (pause, hire staff,
  open park).
- Held-out cases reach 245 blocks that public cases do not; public cases reach 2,306 that
  held-out cases do not.

## Implications and proposed decisions (human review)

1. **Lift boundary.** Proposal: lift all three code sections mechanically, `.text` included
   (the C runtime is ordinary x86 for the same lifter), and make the JS host implement the 104
   OS/COM functions.
   - **Why:** the pins already live at that boundary. The oracle can record every API call's
     arguments and results, which gives the host a per-call oracle of its own.
   - **Alternative:** replace `.text` with hand-written JS (59 functions, the main loop, the
     window procedure, 41 shared variables). That's a smaller surface, but it isn't mechanical
     and has no per-call oracle.
2. **Comparator.** Proposal: Stage 1 gate = `rng` + `masked` (+ commands) exactly, per tick,
   on the corpus. Reproducing Wine's addresses (CSG1 at `0x03C80000`, DIB at `0x019A0000`) is
   possible and would allow the raw `core` hash, but it ties the lift to Wine.
3. **Execution model.**
   - The lift has to keep a real x86 stack in emulated memory, since the game long-jumps
     through a saved `esp` and the C runtime unwinds SEH frames.
   - It needs exact flags at 8, 16 and 32 bits that survive returns, and code bytes readable at
     their original addresses.
   - Unresolved indirect targets need a dispatch that can fall back to an interpreter for
     blocks not in the map. None have been observed, but 334 indirect sites are unresolved.
   - Ahead-of-time translation is sufficient (M3).
4. **Corpus growth is in scope for Stage 1.**
   - 46 of 49 commands have no confirmed register conventions. The method that works: drive
     the real UI with `mouse` script actions and read `TR_COMMAND` records (`oracle/README.md`).
   - Also needed: locked scenarios 5–21, saved-game loading, long runs (months and years:
     finance, research, weather, breakdowns), multi-tick frames (`RCTHOOK_QUANTUM`), UI input
     through the click queue.
   - **Decision:** the coverage target that makes a Stage 1 acceptance meaningful, for example
     ≥ 50% of CODESEG instructions with every executed command family represented.
5. **Host recordings.** Record the OS answers listed in M7 (and every call to the 104
   functions, with arguments and results) as the host's contract. These recordings are the
   user's environment data: they live in `out/`, never in the repo.
6. **Throughput target.** Note that 50–250M emulated instructions/s matches the oracle. If the
   lift is also to replace the oracle for Stage 2's per-function captures, it should run faster
   than the oracle.

## Proposed Stage 1 work order

1. **API trace in the oracle:** record every call to the 104 functions with arguments and
   results. This is the JS host's per-call oracle, and it records the unpinned answers.
2. **Lifter core:** decode from the v2 map; one JS function per block (or per region);
   emulated memory = image + mapping + DIB + heap pages + stack; flags; string ops; partial
   registers.
   - Unit-gate it with instruction-level differential tests against single-step captures
     (`istep` extended to record registers).
3. **Host:** the 104 functions under the oracle's pins; file I/O against the user's game files;
   the CSG1 mapping; the DIB; the virtual clock; fake DirectInput; the click queue; the window
   procedure path.
4. **Lift gate:** whole-run traces from the lift vs oracle traces, `rng` + `masked` + commands,
   first divergence localised by chunk hashes and, when needed, by single-stepped
   instruction traces from the oracle.
5. **Corpus growth** in parallel with steps 2–4: command discovery, scenarios, saved games,
   long runs, with coverage tracked by the breakpoint instrument as the second instrument that
   says what the gate covers.

## Instruments built for these spikes

| Instrument | What it gives | Self-check |
|---|---|---|
| `RCTHOOK_SPIKE=codewatch` | per-frame code-section diffs | detects a 1-byte poke |
| `RCTHOOK_SPIKE=apicount` | call counts for every import, GetProcAddress result and DirectDraw method | n/a (counting thunks) |
| `RCTHOOK_SPIKE=heapshift=N` | shifts the heap, mappings and handle numbers | RNG unchanged across the whole corpus |
| `RCTHOOK_SPIKE=memmap` | committed memory regions at quit | n/a |
| `RCTHOOK_SPIKE=istep=A:B` | per-tick instruction counts, executed-instruction bitmap | RNG and masked state unchanged |
| `RCTHOOK_SPIKE=cover=FILE` | one-shot `int3` coverage (checksummed range armed after frame 1) | reports all 13,640 stepped addresses except the 4 hook sites; RNG unchanged on all 7 cases |
| `tools/rctcfg.py` | static code map (v2) | dynamic cross-check: 0 executed addresses missing |
| `tools/coverbisect.py` | finds breakpoint addresses that break the game | found the 6 v1 false positives |
| `tools/ptrmask.py`, `tools/dumpdiff.py` | OS-derived dwords; dump diffs | consistent across 7 cases |
| `TR_MSTATE` / projection `masked` | layout-independent state hash | layout shift identical; cash mutant detected |

Environment fixes made along the way:

- **Disk.** Run prefixes hard-link `drive_c/windows`, whose pristine files are read-only. The
  rest is copied, cutting disk per run about 4.5× (48 concurrent runs filled the disk before).
- **Call sites.** Injected commands record the call site as `0xFFFFFFFF`, so traces don't
  depend on the hook DLL build.
- **Modal dialogs.** Any modal dialog ends a run immediately, with its text and a backtrace,
  instead of hanging until the timeout. The game's own startup dialog is modeless and allowed.
