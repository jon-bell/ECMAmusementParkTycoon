# The oracle runtime

`rct.exe` (v1.08.183, English) runs unmodified under 32-bit Wine on a private Xvfb display.
`rcthook.c` is built as `dinput.dll` and placed next to `rct.exe` in the run's copy of the
prefix (`WINEDLLOVERRIDES=dinput=n`). `rct.exe` imports `DINPUT.dll`, so Wine's loader maps the
hook while binding the game's imports. The hook's `DllMain` runs after every import is bound and
before the game's entry point. It patches IAT slots and inserts inline hooks; the file on disk is
never touched. It then:

1. **pins** every nondeterministic input the binary consumes (table below);
2. **records** a binary trace (`trace.h`): every RNG draw, every tick's RNG state and state hash,
   every game command;
3. **replays** an input script of game-level actions.

## Hook points (rct.exe addresses)

| Address    | What                                   | Hook records |
|------------|----------------------------------------|--------------|
| `0x5DF40C` | scenario RNG: `srand0 += ror(srand1 ^ 0x1234567F, 7); srand1 = ror(old srand0, 3)`; returns `srand1` in eax. State at `0x6E3B88`/`0x6E3B8C`. 111 call sites. | at `0x5DF42A`: tick, call site, value |
| `0x43888E` | first instruction of a logic tick (the tick loop in the frame function) | tick start: RNG state, state hashes; runs `tick` actions |
| `0x4385D8` | per-frame function called by the main loop at `0x4010F7` | frame count |
| `0x4386EC` | frame body, after the frame saved `esp` in `[0x991F6C]` | runs `frame` actions |
| `0x426F56` | `game_do_command`: `esi` = command (table `0x5F49A0`, 49 entries), `bl` bit 0 = apply, result in `ebx` (`0x80000000` = failure) | every call with registers |
| `0x43054E` | start new game from scenario `#ax`: seeds the RNG (`timeGetTime() ^ srand0`), loads `Scenarios\SC<ax>.SC4`, opens the main windows, then long-jumps to the main loop through `[0x991F6C]` | used by `load` |

The state hash covers DATASEG `[0x5F4000, 0x9A161C)` and DataSeg `[0x9A2000, 0x9B2301)`, as
FNV-1a over 32-bit words: one 64-bit hash per tick, plus one per 64 KiB chunk so that a divergence
can be localised.

A second, **masked** hash (`TR_MSTATE`) reads 38,373 OS-derived dwords as 0:

- the CSG1.DAT sprite pointers at `0x8DC0B4 + 16·i`;
- the DIB and mapping pointers;
- one file handle.

The list and the evidence for it are in `rcthook.c` and `docs/stage1-scope.md` (M5). The raw
hash depends on where Wine put memory; the masked one does not. The gate checks the masked one
against a layout-shifted run of every case.

## Pins

| Source | Where it reaches the game | Pin |
|---|---|---|
| `timeGetTime`, `GetTickCount` | frame pacing (`0x4386EC`: `ticks = clamp(Δ/31, 1, 4)`, then busy-waits ≥ 25 ms); **RNG seed** at `0x43054F` | virtual clock: starts at 5 000 000 or the script's `seed`, advances 1 ms per query. Busy-waits terminate and every frame runs exactly one tick. |
| `Sleep` | sound code | advances the virtual clock, returns immediately |
| `GetSystemTime` | date fields at `0x5F1CA4`… | 2000-01-13 12:00 + virtual elapsed time |
| `SetTimer` (1 s) | `WM_TIMER` | no OS timer; `WM_TIMER` is synthesized from the virtual clock when the queue is empty (not called in practice) |
| `timeSetEvent` (50 ms sound callback `0x40C8A6`, runs on another thread) | sound channels | not started |
| `DirectSoundCreate`/`Enumerate` | sound | `DSERR_NODRIVER`: the game runs silent and starts no audio thread |
| `DirectInputCreateA` | keyboard (256 bytes) and mouse (deltas, buttons) polled every frame (`0x4071E2`, `0x4070F8`) | in-process fake devices; state comes only from the script (`key`) |
| window messages | mouse/keyboard via the window procedure `0x403D79` into the click queue `0x5F1CC0` | input messages are dropped and logged; clicks come only from the script (`mouse`) |
| `GetCursorPos`/`SetCursorPos` | hover, tooltips, cursor | virtual cursor at (1000,740) unless the script moves it (`cursor`) |
| `GetComputerNameA`, `GetUserNameA`, `GlobalMemoryStatus`, `GetDiskFreeSpaceA` | machine identity and resources | fixed values |
| `FindFirstFileA`/`FindNextFileA` | scenario list (`Scenarios\*.SC4`), saved games | sorted by name, fixed timestamps |
| 8.3 alias of `D:\Saved Games` | **copy protection** at `0x42F1D3`: the alias must have `~` at index 5, or flag `0x5F853C` stays set and the objective window (handler `0x428649`) quits every new game to the title | aliases on D: are reported Windows-style (`SAVED~1`). Wine's hashed alias `SAVE~YWG` fails the check. *Assumption, needs human review:* this is what the genuine disc yields under the period OS. The check proves only that the original environment put `~` at index 5. |
| prefix contents (`SC.IDX`, `game.cfg`, scores, registry) | written by the game | every run copies the pristine `game/prefix` and discards the copy |
| screen size | `GetSystemMetrics`: screen buffer 1024×768, game area 640×480 | Xvfb `1024x768x24` |

Environment notes:
- Ubuntu's Wine 9.0 `wineserver` aborts with `free(): invalid pointer` when `TMPDIR` is set. Every
  script unsets it.
- With no window manager the game window sits at screen (36,62), not (0,0). Real X clicks
  therefore land offset from where the hover suggests. Use the script's `mouse` action, which
  writes game coordinates straight into the game's own click queue.
- Wine finds no GL, Vulkan or ALSA here. DirectDraw falls back to GDI rendering, which is fine:
  the framebuffer is not part of any Stage 0 projection.

## Trace

16-byte records `{kind, a, b, c}`; kinds are in `trace.h`. `tools/rcttrace.py` reads them:

```
python3 tools/rcttrace.py summary out/runs/x/trace.bin
python3 tools/rcttrace.py compare A/trace.bin B/trace.bin [core|game|input|os|game+input]
python3 tools/rcttrace.py rng out/runs/x/trace.bin 50
```

Projections:

| Projection | Records |
|---|---|
| **rng** | RNG draws and per-tick RNG state |
| **masked** | rng + the masked state hash |
| **core** | RNG, raw and masked state hashes, chunk hashes, final hash |
| **game** | core + commands with registers, injected-command results, loads, totals |
| **input** | what the script applied |
| **os** | frames, the virtual clock, window messages, file opens |

Commands injected by a script record call site `0xFFFFFFFF`, so traces don't depend on the hook
DLL's build.

## Input scripts

One action per line, `#` starts a comment. Actions run in file order; each waits for its time.

```
seed <n>                      virtual clock at process start (selects the scenario RNG seed)
frame <n>  <action>           at frame n of the run
frame +<n> <action>           n frames after the last scenario load completed
tick <n>   <action>           at the start of logic tick n (ticks count from the last load)

load <scenario>               start a new game from Scenarios\SC<n>.SC4 (as the scenario-select
                              window does, 0x4304A7); waits until the intro has finished
cmd <id> [eax=..] [ebx=..] [ecx=..] [edx=..] [edi=..] [ebp=..]
                              game_do_command with esi=<id>; result registers are traced
call <addr> [regs...]         call any routine with registers (discovery)
key <dik> <0|1>               DirectInput keyboard key state (DIK scan code)
cursor <x> <y>                virtual cursor (screen coordinates)
mouse <x> <y> <ev>            push a click into the game's queue (game coordinates);
                              ev 1 left down, 2 right down, 3 left up, 4 right up
poke <addr> <mask>            XOR a byte (fault injection for gate self-tests only)
dump                          write DATASEG+DataSeg to dump_*.bin
fb                            write the game's 8-bit screen buffer (palette indices) as PGM
shot                          write the game window as BMP (debug aid)
quit                          record the final state and end the run
```

Command conventions confirmed against the binary, by capturing what the real UI issues
(`mouse` clicks on the real windows, `TR_COMMAND` records):

| id | command | registers |
|---|---|---|
| 2  | toggle pause | `ebx=1` |
| 28 | hire staff (left unplaced) | `eax=0x8000 ebx=1\|type<<8` (type 0 handyman) |
| 33 | set park open | `ebx=1 edx=0x100` opens (`dh=1`), `edx=0` closes; park flags `0x87C3BC` bit 0 |

RCT1's command numbering differs from RCT2's beyond the first few entries. Confirm every
convention with a UI capture before relying on it.

## Failure modes

- A malformed or unreadable script is fatal (exit 3, `FATAL` in `hook.log`).
- Any modal dialog (`MessageBoxA`, e.g. the game's own "Error Trapper", or `DialogBoxParamA`)
  ends the run (exit 4) with its text and a backtrace. The modeless dialog the game creates at
  startup (`CreateDialogParamA` #101) is normal.

## Measurement modes (`RCTHOOK_SPIKE`, `spike.c`)

These are for scoping and debugging only, never for a gate's clean runs. They are
comma-separated:

| Mode | What it does |
|---|---|
| `codewatch` | per-frame diff of the code sections (self-modifying code) |
| `apicount` | call counts per import, per `GetProcAddress` result and per DirectDraw method → `api_counts.txt` |
| `heapshift=N` | shifts heap, mappings and handle numbers before the game starts |
| `memmap` | committed memory regions at quit → `memmap.txt` |
| `istep=A:B` | single-steps game code from tick A through tick B → `istep_ticks.txt` (instructions per tick) and `istep_cov.bin` (executed-instruction bitmap) |
| `cover=FILE` | one-shot `int3` at every address in FILE (uint32 LE) → `cover_hits.bin` |

Breakpoints in the self-checksummed range `0x42EAE0–0x431510` are armed only after frame 1. The
address list must contain only true instruction starts (`tools/rctcfg.py` map v2;
`tools/coverbisect.py` finds offenders).

## Running

```
scripts/oracle-run.sh out/runs/name corpus/public/dynamite-dunes-open.txt [-- RCTHOOK_X=1 ...]
```

Results go to `out/runs/name/`: `trace.bin`, `hook.log`, `summary.txt`, `wine.log`, plus any dumps
or shots. Exit status 0 means the script reached `quit`.
