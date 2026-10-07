# Stage 1 design: the mechanical lift

Read `CLAUDE.md` (principles), `docs/stage1-scope.md` (measurements) and `oracle/README.md` (the
oracle, trace format, script language) first. This document fixes the decisions and interfaces
that every Stage 1 workstream builds against. Change it only deliberately, and say so in your
report.

## Decisions (adopted from the scope document)

1. **Everything is lifted mechanically:** `.text`, CODESEG and CodeSeg, C runtime included. The
   only hand-written semantics are the x86 instruction semantics and the **host**: the Win32
   functions rct.exe imports (104 are called in practice; `docs/stage1-scope.md` M7) plus the
   COM objects behind them.
2. **The lift reproduces the oracle's pinned environment,** not a real Windows. Every pin in
   `oracle/README.md` is reproduced exactly:
   - the virtual clock (start value, +quantum per `timeGetTime`/`GetTickCount` query, `Sleep`
     advances it);
   - `GetSystemTime`;
   - the fake DirectInput, `DSERR_NODRIVER`, dropped user input and the virtual cursor;
   - the fixed machine identity;
   - sorted `FindFirstFile`, its timestamps and the CD aliases.

   Unpinned answers that Wine gives (`GetSystemMetrics`, `EnumDisplayModes`, `GetDeviceCaps`,
   `GetVersion`, startup window messages, ...) are reproduced as **documented constants** in
   host code, justified by the oracle's API trace.
3. **No oracle data at runtime.** The lift must not read traces, dumps or API-trace files while
   running (principle 7). It loads the user's own game files (`rct.exe` and the game directory)
   at runtime. Generated JS is derived from the user's binary: it lives in `out/lift/` and is
   never committed. Lifter, runtime and host source are committed.
4. **Comparator.** A lift run produces a `trace.bin` in the oracle's format (`oracle/trace.h`),
   readable by `tools/rcttrace.py`. The Stage 1 gate requires, per corpus case, identity with the
   oracle on projection **`lift`**:
   - `rng` + `TR_MSTATE` (masked state);
   - `game` without the raw-state records (`TR_STATE`, `TR_CHUNK`, `TR_FINAL`): commands with
     registers, injected-command results, loads, notes, totals;
   - `input`.

   `os` records (frames and virtual clock, messages, file opens) are compared and reported. They
   are expected to match too. Raw `core` identity is a bonus, reachable if the host places the
   CSG1 mapping, the DIB and the file handles where Wine did.
5. **Ahead-of-time translation** from the static code map v2 (`tools/rctcfg.py` →
   `out/spikes/s1/cfg.json`). No self-modifying code exists (scope M3). Code bytes stay readable
   at their original addresses in guest memory (scope M4). An eip not in the map is a hard error
   naming the address (`MissingBlock`). Such addresses are fixed by adding seeds, never by
   guessing at runtime.

## Execution model

### Guest memory

One `Uint8Array` of `MEM_SIZE = 0x05400000` bytes covering guest addresses `[0, MEM_SIZE)`.
Little-endian. Unaligned access is allowed. An access outside it throws `GuestFault`.

| Range | Content |
|---|---|
| `0x00230000–0x00330000` | main thread stack. Initial `esp` = `0x0032FF00`, unless the oracle's API trace shows a better value. |
| `0x00400000–0x009BD000` | the PE image: headers + sections at their RVAs, loaded at runtime from the user's `rct.exe`. Uninitialised tails are zero. The IAT holds host-function addresses. |
| `0x00A00000–0x01990000` | host heap arena (`HeapAlloc`, `GlobalAlloc`, `VirtualAlloc`, `malloc` via the C runtime's own heap on top of `HeapCreate`/`HeapAlloc`) |
| `0x019A0000` | DIB section bits (1024×768×8), as under Wine |
| `0x03C80000` | CSG1.DAT file mapping (read-only view), as under Wine |

### Registers and flags

The machine object `m` holds `eax ecx edx ebx esp ebp esi edi eip` as uint32 numbers (normalise
with `>>> 0`). Flags are separate 0/1 fields: `cf pf af zf sf tf df of`. There are helpers
`getEflags()` and `setEflags(v)` (bit 1 always set; IF bit 9 reads as 1). Lazy flag evaluation
is allowed inside the lifter if it is invisible outside a block.

### Code and dispatch

The lifter emits one JS function per basic block. A block runs its instructions and returns the
next eip. Dispatch:

```
while (true) { const f = blocks[eip - IMAGE_LO]; if (f) eip = f(m); else eip = m.special(eip); }
```

`special(eip)` handles host-function addresses, the host-return marker, hook continuations, and
otherwise throws `MissingBlock(eip)`.

Forced block boundaries (blocks must start here so hooks can run before them; list in
`lift/hooks.json`):

| Address | Hook |
|---|---|
| `0x5DF42A` | RNG store; `eax` = drawn value, caller = `r32(esp+4) - 5` |
| `0x43888E` | tick start |
| `0x4385D8` | frame entry |
| `0x4386EC` | frame body |
| `0x426F56` | `game_do_command` entry |

`m.hooks` is a `Map<eip, fn(m)>` that the dispatcher calls **before** executing the block at
that eip. A hook may perform guest calls, or redirect eip by returning a new eip (return
`undefined` to continue normally).

### Host-call ABI

Each imported function gets a magic address `HOST_BASE + 16*i`, with `HOST_BASE = 0xFFF00000`.
The loader writes these into the IAT slots. COM methods get magic addresses the same way (the
host builds vtables in guest heap memory). When eip is a host address, the runtime calls
`impl(m)` with `esp` pointing at the return address:

- `m.arg(i)` = `r32(esp + 4 + 4*i)`;
- the impl sets `m.eax` (and `m.edx` if needed);
- it returns by calling `m.retStd(nargs)` (stdcall: pop return address into eip, pop `nargs`
  dwords) or `m.retCdecl()`.

Flags after a host call are unspecified, as on Windows. Callers in rct.exe do not read them;
the static map shows no flag reads after IAT calls.

### Guest calls from the host

`m.callGuest(addr, {eax, ebx, ...})` saves nothing implicitly. It pushes `HOST_RETURN =
0xFFFFFFF0` as the return address, sets the registers, runs a nested dispatch loop until eip
reaches `HOST_RETURN`, and returns the register file and flags. It is used for:

- window procedures (`DispatchMessage`, `SendMessage`, `CreateWindowEx`, `DefWindowProc` paths);
- dialog procedures;
- enumeration callbacks;
- `cmd` / `call` script actions.

**Long-jump case:** `load` calls `0x43054E`, which on success resets `esp` from `[0x991F6C]` and
returns to the main loop without ever reaching `HOST_RETURN`. The `load` action therefore does
**not** use a nested loop. It pushes `HOST_RETURN_LOAD`, sets `eax`, and redirects eip from the
frame-body hook to `0x43054E` within the outer loop. If `HOST_RETURN_LOAD` is ever reached, the
load failed: log it, continue at `0x4386EC`, and the stale marker below `esp` is harmless. This
mirrors the oracle exactly (`oracle/rcthook.c`, `A_LOAD`).

## Script, hooks and trace

The lift implements the oracle's script language and timing exactly (`oracle/README.md`):

- `frame` actions run at the frame-body hook (`0x4386EC`), and `load` waits until
  `[0x628CB9] == 0`;
- `tick` actions run at the tick hook after the tick counter increments and the tick
  record and state hash are written;
- `frame +N` is relative to the frame of the last completed load;
- the tick counter resets at a completed load.

The trace record sequence must match the oracle record for record, including `TR_HEADER`,
`TR_NOTE` (seed, load success/failure), `TR_FRAME`, `TR_COMMAND` (the call site of injected
commands is `0xFFFFFFFF`), `TR_REGS_*`, `TR_INJ_*`, `TR_MSG`, `TR_FILE` where the host can know
them, and `TR_END`.

State hashing is FNV-1a 64 over 32-bit words of DATASEG `[0x5F4000, 0x9A161C)` and DataSeg
`[0x9A2000, 0x9B2301)`, plus per-64 KiB chunk hashes and the masked hash, exactly as
`record_state` in `oracle/rcthook.c` (same mask list).

## Layout

```
lift/
  lifter.py          map + rct.exe -> out/lift/*.js        (Python, .venv: capstone, pefile)
  hooks.json         forced block starts / hook addresses
  runtime/           machine, memory, flags helpers, dispatcher, loader, host-call ABI
  host/              Win32 + COM, file system, window/message model, pins, script, trace, hashing
  run.js             node lift/run.js --exe <rct.exe> --game <dir> --script <s> --out <dir>
  test/              unit tests (node --test)
scripts/lift-run.sh    lift + run one script (mirrors scripts/oracle-run.sh)
scripts/gate-lift.sh   the Stage 1 gate
```

Node: Ubuntu's `nodejs` (18.x, apt) is the reference runtime. Nothing outside the Node standard
library without a recorded reason.

## Debugging instruments (oracle side)

- **API trace** (`RCTHOOK_SPIKE=apitrace`): every call through the IAT and every COM method,
  with arguments, return value and nesting; also every entry into a guest callback (window
  procedure, dialog procedure, enumeration callback) with its arguments. The lift's host emits
  the same format, so the first API-level divergence can be found mechanically.
- **Register capture** (`RCTHOOK_SPIKE=istep=A:B` + `regs`): the register file and flags at
  every executed game instruction in a tick window. The lift can dump the same at block entries,
  which localises a semantic bug to one block.

## Stage 1 gate (acceptance)

`scripts/gate-lift.sh` runs, for every corpus case (public and held-out), the oracle and the lift
on the same script. It requires identity on projection `lift`, reports `os` differences, and
reports:

- observation counts;
- lifted blocks executed;
- the executed-block set of the lift vs the oracle's breakpoint coverage, which should be equal.

It must reject known-bad lifts before its passes count:

- an `adc` that ignores CF;
- a dropped `stc` before a `ret`;
- a host clock that advances 2 ms per query;
- a host `GetSystemTime` off by one day.

Acceptance also states the coverage the corpus reached (target: at least 50% of CODESEG
instructions; `docs/stage1-scope.md` M9). Code never executed by the corpus is lifted but not
validated, and the report says so.

## As implemented (2026-10-07)

These are the points where the build differs from, or adds to, the plan above. Details are in
`lift/runtime/README.md`, `oracle/README.md` and `docs/wine-answers.md`.

**Code map.** Official map is v4 (`out/spikes/s1v4`, `tools/rctcfg.py`): 92,055 blocks. On top
of v2 it adds:
- OS-called entry points (the window procedure `0x403D79` was missing);
- `loop` targets;
- 610 jump-table dispatch stubs;
- every block start the oracle executed, as trusted seeds.

It is validated by armed breakpoints on every block over all 43 corpus cases.

**Markers.** `HOST_RETURN_LOAD = 0xFFFFFFE0` and `HOST_EXIT = 0xFFFFFFD0`. The `load` target
`0x43054E` is a forced block start.

**Flags.** Computed only where live, and exact at every hook address, `ret`, indirect transfer
and host call. Flags the manual leaves undefined are measured on this machine's CPU (AMD Zen 2).
`cpuid` returns this machine's values: environment-dependent.

**Entry state.** Process entry registers and the stack (`[0x220000, 0x320000)`, `esp`
`0x31FF54`) are as under Wine. The host also places the C-runtime heap, DIB, CSG1 view and file
handles where Wine does, and calls injected actions at the oracle hook's stack depth, so raw state
matches too. The gate itself relies on the masked projection.

**New pins** (oracle and host mirror each other):
- after every OS call the game makes: `ecx = edx = 0`, `eax = 0` for void functions,
  `eflags = 0x202`;
- deterministic `FindFirstFile` handles;
- fixed environment block, `MSG.time` and `MSG.pt`;
- scripted file dialogs (`file`), `quantum`, `char`, `dimouse` and `move` actions.

**Trace.** Format version 3 adds `TR_REGS_IN3`/`TR_INJ_IN3` (`ebp` and flags) and `TR_BUILD` (a
hash of the producer's sources). The mask lives in one file, `oracle/mask.h`, read by both
oracle and host.

**Gate.** Three stages plus mutants:
- trace (projection `lift`);
- coverage cross-check (the lift's executed blocks must equal the oracle's breakpoint hits);
- a **register stage** (two single-stepped tick windows per case, `tools/stepdiff.py`), added
  because the trace stage was measured blind to some flag faults (see the gate report).
