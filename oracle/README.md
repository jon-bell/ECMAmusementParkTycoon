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

A second, **masked** hash (`TR_MSTATE`) reads the OS-derived state bytes listed in
`oracle/mask.h` as 0. That file is the single list shared with the JS host: one `MASK_DWORD(addr)`
or `MASK_STRIDE(base, stride, count)` per line; a masked byte contributes 0 to its 32-bit word.
The entries:

- the CSG1.DAT sprite pointers at `0x8DC0B4 + 16·i` and the view pointers at `0x9A2008`–`0x9A2010`;
- the bits pointers of the six drawing contexts (`0x5F96C0`, `0x5F96D0`, `0x99FB7C`, `0x99FB8C`,
  `0x99FE08`, `0x9A012C`);
- a malloc'd buffer pointer (`0x628C44`);
- the scenario file handle (`0x5F88A4`) and 22 cursor handles (`0x9A1550`).

The evidence is in `docs/stage1-scope.md` M5 and its addendum: per-tick pointer scans and
change logs of clean vs layout-shifted runs over 61 scripts, with 0 uncovered bytes, plus a
static enumeration. To re-audit:

```
# phase 1: RCTHOOK_SPIKE=ptrscan, clean (<case>-base) and with heapshift=200003 (<case>-shift)
python3 tools/maskaudit.py candidates DIR -o LIST.bin
# phase 2: RCTHOOK_SPIKE=watch=Z:/abs/path/LIST.bin, same pairs (forward slashes: xargs eats backslashes)
python3 tools/maskaudit.py diff DIR          # exit 1 if a layout-dependent byte is not masked
```

`heapshift=N` shifts the heap, global and virtual memory, kernel handles, and (since Stage 1)
USER and GDI handle numbers. The raw
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
| `GetOpenFileNameA`/`GetSaveFileNameA` (File > Load/Save, `0x40871F`) | the saved-game path | never shown (modal). Answered by the script's `file` action: `lpstrFile` = `<directory of rct.exe>\Saved Games\<name>`, `nFileOffset`/`nFileExtension` set, `lpstrFileTitle` = `<name>`, TRUE; otherwise FALSE (cancel). `TR_NOTE` 4 records 1 (answered) or 0 (cancelled) |
| DirectInput mouse | drag tools: held buttons and movement deltas (`0x4070F8` → `.data` `0x5F128C` lX, `0x5F1280` lY, `0x5F1284..87` buttons, `0x5F1288` any button) | zero unless the script's `dimouse` sets them |
| `PeekMessageA` `MSG.time`, `MSG.pt` | the message the main loop passes to `TranslateMessage`/`DispatchMessageA` | `time` = the virtual clock (not advanced), `pt` = the virtual cursor (Wine stamps the real tick count and cursor) |
| `GetCursorPos`/`SetCursorPos` | hover, tooltips, cursor | virtual cursor at (1000,740) unless the script moves it (`cursor`) |
| `GetComputerNameA`, `GetUserNameA`, `GlobalMemoryStatus`, `GetDiskFreeSpaceA` | machine identity and resources | fixed values |
| registers after OS calls | values Wine's (or the pins' compiled) code leaves in ecx, edx, eax and eflags; the game observes some (e.g. eax's upper half after `GetSystemTime`) | after every call game code makes through the IAT, a `GetProcAddress` result or a COM method, the thunk sets ecx = 0, edx = 0 (unless the signature returns edx:eax, kind `q`; none does), eax = 0 for functions returning nothing (kind `v`) and eflags = `0x202`. The signature table is `apisig.txt`. Thunks: `apitrace.c`, always installed; recording only with `apitrace`. Calls made by the OS or by the oracle are not touched |
| `GetEnvironmentStrings(W)` | the C runtime's environment copy (`_environ`, heap); never reaches DATASEG (the gate's environment padding shows no effect) | a fixed block: `COMSPEC=C:\windows\system32\cmd.exe`, `PATH=C:\windows\system32;C:\windows`, `SystemRoot=C:\windows`, `TEMP=C:\windows\temp`, `TMP=C:\windows\temp`, `windir=C:\windows` (the real one varies with the run directory and settings). `FreeEnvironmentStrings*` of it succeeds |
| `FindFirstFileA`/`FindNextFileA` | scenario list (`Scenarios\*.SC4`), saved games; the search handle is kept in DATASEG (`0x5F9427`) | sorted by name, fixed timestamps; search handle `0x46490000 + 4·slot` (lowest free slot of 16; `FindClose` frees it) |
| 8.3 alias of `D:\Saved Games` | **copy protection** at `0x42F1D3`: the alias must have `~` at index 5, or flag `0x5F853C` stays set and the objective window (handler `0x428649`) quits every new game to the title | aliases on D: are reported Windows-style (`SAVED~1`). Wine's hashed alias `SAVE~YWG` fails the check. *Assumption, needs human review:* this is what the genuine disc yields under the period OS. The check proves only that the original environment put `~` at index 5. |
| prefix contents (`SC.IDX`, `game.cfg`, scores, registry) | written by the game | every run copies the pristine `game/prefix` and discards the copy |
| screen size | `GetSystemMetrics`: screen buffer 1024×768, game area 640×480 | Xvfb `1024x768x24` |

Environment notes:
- Ubuntu's Wine 9.0 `wineserver` aborts with `free(): invalid pointer` when `TMPDIR` is set. Every
  script unsets it.
- Coordinates. `mouse` writes game (client) coordinates into the click queue `0x5F1CC0`, which is
  where the window procedure puts a button message's lParam (it also keeps it in `.data`
  `0x5F1CB4`/`0x5F1CB8`, which only the queue writer `0x403454` reads). `cursor` sets the virtual
  cursor that `GetCursorPos` returns, in screen coordinates. `GetCursorPos` is called through the
  wrapper `0x4058F8`; the corpus API traces show which sites call it (`docs/wine-answers.md`).
  `GetCursorPos` is called only by the frame function's initialisation (`0x438762`, `0x4389F1`),
  which stores it in DATASEG `0x628CD0`/`0x628CD4`. The hover position is `.data`
  `0x5F1A10`/`0x5F1A14` (read by `0x5E1F70` into DATASEG `0x99FDF4`/`0x99FDF8`), set only by the
  window procedure on `WM_MOUSEMOVE` (`0x40410B`), which the input pin drops: use `move`.
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

**Trace version 2** (`TR_HEADER` a = 2) adds two records:

- `TR_REGS_IN3` (`0x19`; projection `game`) follows `TR_REGS_IN2` at every `game_do_command`
  entry: `ebp`, `eflags & 0xCD5` (CF PF AF ZF SF DF OF), 0. Command handlers receive `ebp` too.
- `TR_INJ_IN3` (`0x1A`; projection `input`) follows `TR_INJ_IN2` for every injected `cmd`/`call`:
  `ebp`, `eflags & 0xCD5`, 0.

**Trace version 3** (`TR_HEADER` a = 3) adds `TR_BUILD` (`0x1B`), always the second record: build id
low 32 bits, high 32 bits, producer (0 = oracle, 1 = lift host). The oracle's id is the first 64
bits of the SHA-256 of its sources (`oracle/Makefile`: every source, `mask.h`, `apisig.txt`, the
Makefile). `hook.log` starts with it. No projection compares `TR_BUILD`.
`tools/rcttrace.py compare` prints `WARNING: build ids differ` when the two traces' ids or
producers differ, and the Stage 0 gate fails a case whose runs mixed builds.
(`scripts/oracle-run.sh` rebuilds the DLL unless `ORACLE_BIN` is set, so ad-hoc comparisons can
otherwise mix builds silently.)

The registers of an injected call are fully defined: those the script names, 0 for the rest, and
eflags = (script `eflags=` & `0xCD5`) | `0x202` (so DF = 0 and IF = 1 by default). `call_asm` loads
eflags with `popfd` before the call. A `load` enters `0x43054E` with eflags `0x202`. When an
injected `cmd` returns `ebx = 0x80000000`, `hook.log` gives the game's error string id (the word at
`0x991EFC`).

## Input scripts

One action per line, `#` starts a comment. Actions run in file order; each waits for its time.

```
seed <n>                      virtual clock at process start (selects the scenario RNG seed)
quantum <n>                   virtual ms per time query (default 1, or RCTHOOK_QUANTUM); recorded in
                              TR_HEADER c. 40 gives 3 logic ticks per frame
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
dimouse <dx> <dy> <buttons>   DirectInput mouse: dx, dy (signed) add to the deltas the next
                              GetDeviceState returns (then reset); buttons (bit i = button i held)
                              persist until the next dimouse. Drag tools (land, water, ...) read the
                              held buttons and deltas only from here (0x5E2110 ff.)
move <x> <y>                  WM_MOUSEMOVE at game (client) coordinates, no buttons, posted to the
                              game window: the hover position (0x5F1A10/14 -> 0x99FDF4/8); also
                              moves the virtual cursor to (x, y)
char <c>                      WM_CHAR <c> (a single character, or a number) posted to the game
                              window; it arrives through the queue at the game's next PeekMessage
file <name>                   the next GetOpenFileNameA/GetSaveFileNameA answers
                              <game dir>\Saved Games\<name> (no spaces); without one it cancels
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
| `regs` | with `istep`: eip, the 8 registers and eflags at every stepped game instruction, and every memory write → `istep_regs.bin` (below) |
| `wmem=LO-HI` | with `regs`: record only writes to `[LO, HI)`; `wmem=none` records none |
| `apitrace` | every OS call, COM call and OS-to-game callback, as the game sees it → `apitrace.txt` (below) |
| `cover=FILE` | one-shot `int3` at every address in FILE (uint32 LE) → `cover_hits.bin` |
| `ptrscan` | every tick, every state dword (2-byte steps; changed words only after the first scan) whose value points into OS memory (mapped, private, another module's image, the stack) → `ptrscan.txt` (address, class, first/last tick, hits, first/last value) |
| `watch=FILE` | every tick, every address of FILE (uint32 LE) whose dword changed → `watch.bin` (uint32 LE triples tick, address, value) |

`RCTHOOK_PERTURB="<name>[#K]:ret^MASK;<name>:outN@OFF^MASK"` (with `apitrace`) XORs what the
game receives from an OS call, at every call or only the K-th: the return value, or the dword at
offset OFF of the memory argument N points to, after the call. It is an experiment, not an oracle:
comparing the run's `trace.bin` with an unperturbed `apitrace` run shows whether that answer
reaches game state (`docs/wine-answers.md`).

All of the hook DLL's own memory sits at fixed addresses that Wine leaves free
(`0x10000000`–`0x3FF00000`), so Wine places the game's memory where it would without the hook, in
every run and for every script:

| Address | What | When |
|---|---|---|
| `0x5EA70000` | register-pin / API-trace thunks (16 bytes each): the function values the game holds | every run |
| `0x20000000` | the thunks' private stack, signature table, bookkeeping | every run |
| `0x3C000000` | `FindFirstFileA` result sets (16 × 512 entries) | every run |
| `0x3D000000` | the script's actions | every run |
| `0x3E000000` | the mask table | every run |
| `0x10000000` | `apitrace.txt` buffer | `apitrace` |
| `0x24000000`, `0x28000000` | `istep` bitmap, register capture buffer | `istep` |
| `0x2C000000` | `ptrscan` / `watch` tables | those modes |

The layout the game sees is then Wine's own: heap `0x1920000`, CSG1.DAT view `0x3C80000`, DIB
`0x19A0000`. Two earlier versions of the hook moved it, which is how the table above came about:
a 4 MiB `.bss` array, and a script-length-dependent `realloc` of the action list (long scripts gave
`0x1A20000` / `0x3CA0000` / `0x52E0000`). Also,
`apitrace.txt` and `istep_regs.bin` are kept in memory and written at quit, so an instrument run
receives the same heap addresses and handle numbers as a clean run. `apicount` and `apitrace`
are exclusive.

Breakpoints in the self-checksummed range `0x42EAE0–0x431510` are armed only after frame 1. The
address list must contain only true instruction starts (`tools/rctcfg.py` map v2;
`tools/coverbisect.py` finds offenders).

## API trace (`RCTHOOK_SPIKE=apitrace`)

`apitrace.c` wraps every slot of rct.exe's IAT (after the pins, so it records what the game
receives), every procedure the game resolves with `GetProcAddress`, and the vtables of the COM
objects the game obtains (`IDirectDraw`, the fake DirectInput objects, and any surface, palette or
clipper). It records calls whose return address lies in rct.exe (`0x401000`–`0x9BD000`) made on
the main thread; calls made by the OS or by the oracle itself are not recorded. Callbacks into game
code are recorded where they happen: the window procedure (behind the input pin of `rcthook.c`),
dialog procedures and enumeration callbacks (the oracle passes a recording trampoline to the OS in
place of the game's pointer and restores the argument afterwards).

Non-perturbation: the thunks run all C code on a private stack, restore the stale return-address
slot below `esp` after the call, and change no register or flag. The trace is kept in memory at a
fixed address and written at quit (opening the file earlier shifted the game's file handle
numbers). The process-entry record comes from a one-shot `int3`. Measured on the 7 cases of the
Stage 0 corpus: `game+input`, raw `core` and `os` are identical to the gate's untraced
references, and `heapshift` + `apitrace` runs are identical on `masked`. On the title case, two
runs with different environments give canonically identical API traces (349,783 records). Corpus
results: `docs/wine-answers.md`.

### Format (version 1)

`apitrace.txt` is ASCII, one record per line (LF), fields separated by exactly one space; no field
contains a space. Numbers are lowercase hexadecimal without `0x` or leading zeros (`0` is zero),
except buffer and allocation lengths, which are decimal. Record types:

```
# <text>                                              annotation; never compared
B 0 0 0 entry <eip> <esp> <eax> <ebx> <ecx> <edx> <esi> <edi> <ebp> <eflags> <[esp]> <[esp+4]> <[esp+8]> <[esp+12]>
C <frame> <tick> <depth> <ret> <esp> <name> <arg>...  a call made by game code
R <depth> <name> <retval> <outarg>...                 its return
B <frame> <tick> <depth> <kind> <target> <esp> <arg>... game code entered by the OS
E <depth> <kind> <retval> <outarg>...                 that callback's return
```

- The first line is `# apitrace 1`; the last is `# end records=.. errors=.. other_thread_calls=..
  open=..`. `# drop <frame> <tick> <depth> msg=<m> w=<w> l=<l>` marks an input message the pin
  dropped before the game saw it. The JS host need not emit any `#` line.
- `entry`: registers and the top of the stack when the game's entry point `0x412E80` runs. It is
  the first record and is not closed by an `E`.
- `frame`: number of entries into the frame function so far (`TR_FRAME`). `tick`: the trace's tick
  counter (reset when a scenario load completes). Both are the values when the record is written.
- `depth`: number of open `C` and `B` records (not yet closed by `R`/`E`) before this one.
- `ret`: the call's return address. `esp`: the game's `esp` on entry to the callee, pointing at the
  return address. For `B`, `esp` is an address on the OS side above the callback's frames (the
  oracle reports its trampoline's frame); it is not comparable between implementations.
- `name`: the import's name as in rct.exe's import table (`ReadFile`); ordinal imports as
  `<dll>#<n>` (`DPLAYX.dll#1`); procedures from `GetProcAddress` by the name the game passed
  (`DirectDrawCreate`, or `#<n>`); COM methods as `Iface::Method` (`IDirectDraw::EnumDisplayModes`,
  `this` is argument 1). `kind` is a callback kind of `apisig.txt` (`wndproc`, `dlgproc`,
  `enummodes`, ...).
- Arguments: all of the signature's arguments, in order, rendered by their kind; arguments of an
  out kind (prefix `o`) appear in `C`/`B` as the raw pointer. `R`/`E`: the return value, then every
  `o`/`io` argument in signature order, rendered after the call. For `msgl` in `E`, only when the
  message's direction in `apisig.txt` is `io`.

### Kinds (`oracle/apisig.txt`)

`fn <name> <std|cdecl> <ret> <arg>...`; an argument kind is `[o|io]<base>`. A length `L` is `N`
(value of argument N, 1-based), `*N` (dword at argument N, read after the call), `r` (return
value), `=N` (constant), `dN` (image size of the `BITMAPINFO` at argument N:
`|biHeight| * ((biWidth*biBitCount + 31) / 32 * 4)`), optionally followed by `xM` (times M). A
length of `0xffffffff` means "not given".

| Base | Token |
|---|---|
| `x` `h` `p` `cb:K` | the dword. `h` is an OS-chosen handle, `p` a pointer; comparison canonicalises both |
| `s`, `s@L` | `0` if NULL; `#<hex>` if below `0x10000` (resource id, atom); else `<ptr>="<chars>"`. Input strings run to the NUL, or exactly L bytes if L is given; output strings (`os`) run to the NUL within L bytes. Bytes `0x21`–`0x7e` except `" \ { } ,` appear literally, every other byte as `\xHH`. At most 1024 bytes; a `~` after the closing quote marks truncation |
| `ws`, `ws@L` | as `s`, `<ptr>=L"<chars>"`, characters 0x80 and above or outside the literal set as `\uHHHH`; L counts characters |
| `g` | `<ptr>={xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` |
| `S:T` | `<ptr>={<hex of sizeof T bytes>}` then `,<string token>` for each `s4` field of T in order. Bytes the callee does not define appear as `..` instead of two hex digits: the bytes after the first NUL of a `cN` (char array) field, and every byte of a `uN` (unused/padding) field |
| `b@L` | `<ptr>=<L>:<FNV-1a 64 of the L bytes, 16 hex digits>`; `<ptr>=?` if L is unknown or above 64 MiB |
| `x@L` | `<ptr>={<hex of L bytes>}` (L ≤ 4096) |
| `dx` `dh` `dp` `I:Iface` | `<ptr>=<hex of the dword at ptr>` (`I`: an interface pointer the game receives) |
| `da@L` | `<ptr>=<hex dword>:<L>` (memory the OS allocated for the game) |
| `lpal` | `<ptr>={<hex of 4 + 4*palNumEntries bytes>}` |
| `bmi@N` | `<ptr>={<hex of the 40-byte header>},<len>:<hash>` of the colour table: 12 bytes if `BI_BITFIELDS`, else n·(argument N = 1 ? 2 : 4) with n = `biClrUsed` or, if 0, `1<<bpp` for bpp ≤ 8 |
| `msgl` | lParam of a window/dialog message: per `msg` lines (string, struct; `NCCALC` = `NCCALCSIZE_PARAMS` if wParam ≠ 0 else `RECT`), else the dword |

An out or io kind may end in a condition: `?` (return value ≠ 0), `?0` (= 0), `?-1`
(≠ `0xffffffff`). When the condition is false the callee wrote nothing there, and the token is
`<ptr>=-` (e.g. `PeekMessageA`'s MSG when it returns FALSE, a failed `RegQueryValueExA`).

Returns: `x h p` the dword; `v` (void) `-`; `s` a string token; `a@L` `<hex>:<L>`; `eas`/`ews` a
buffer token over the environment block including its terminating double NUL. A NULL pointer is
`0` in every kind; unreadable memory is `!` in place of the content. Hash: FNV-1a 64
(`h = 0xcbf29ce484222325; for each byte: h ^= b; h *= 0x100000001b3`). A name with no signature is
logged in `hook.log`; its `C` line has `?` for arguments and its `R` line `nargs=<n>`. At each
return the oracle checks the number of argument bytes the callee popped against the signature and
logs `# warn` on a mismatch.

### Tools

```
python3 tools/apitrace.py check  out/runs/x/apitrace.txt     # nesting, names, signatures
python3 tools/apitrace.py dump   out/runs/x/apitrace.txt [--grep RE] [--canon]
python3 tools/apitrace.py diff   A/apitrace.txt B/apitrace.txt [--raw] [--ignore NAME,..]
python3 tools/apitrace.py shapes out/runs/*/apitrace.txt [--canon] [--name RE]
```

`diff` compares canonical forms and reports the first divergence with the open calls. Handles are
named in creation order (`H1`, ...; a handle closed by `CloseHandle`, `RegCloseKey`, ... can be
reused). Pointers into memory the OS allocated for the game become `A<n>+off` or `D<n>+off`. Stack
pointers become offsets from the record's `esp` (`sp+1c`); inside callbacks, pointers into OS
frames become `stk`. `GetProcAddress` results become `proc(<name>)`. The `esp` of a `C` record is
compared as an offset from the entry `esp`, except inside callbacks. `B` `esp` and the entry
eflags are not compared.

## Register capture (`RCTHOOK_SPIKE=istep=A:B,regs[,wmem=LO-HI]`)

From the start of tick A to the start of tick B+1 the oracle single-steps every instruction of
rct.exe. Stepping pauses when game code calls or jumps out of the image and resumes at the
return address. Game code entered from outside while stepping (the window procedure, routines
called by script actions) is stepped too. Instructions an inline hook displaced into its stub are
recorded at their original address, and the hook's own instructions are not recorded. Values the
stub's relocated `call` pushed are rewritten to the original return address. `istep_regs.bin` is
little-endian:

```
header  16 bytes  u32 magic 0x50545352 ("RSTP"), u32 version 1, u32 flags, u32 0
                  flags bit 0: 1 = one R per executed instruction (oracle), 0 = one R per block entry (lift)
R  44 bytes  u32 0x52 | rflags<<8, eip, eax, ecx, edx, ebx, esp, ebp, esi, edi, eflags
             registers before the instruction at eip executes; eflags without TF and RF.
             rflags: 1 another iteration of a rep-prefixed string instruction (same eip),
                     2 first instruction after an OS call returned,
                     4 first instruction of game code a script action calls (cmd, call, load),
                     8 first instruction of game code the OS calls (window procedure)
W  12 bytes  u32 0x57 | size<<8, addr, value    a write by the preceding R's instruction
             (size 1, 2 or 4; wider writes are split into 4-byte pieces, in address order);
             the value is read back after the instruction, so a write of the old value is recorded too
T   8 bytes  u32 0x54, tick                       the tick hook ran: before the tick's script actions
                                                  (whose game code follows) and its first instruction
O  12 bytes  u32 0x4F, iat_slot, return address   game code called/jumped out (OS or hook code);
             iat_slot = address of the IAT slot for call/jmp [disp32], else 0
```

A rep-prefixed `stos`/`movs` traps after every iteration and records one element per step; with a
count of 0 it records no write. After a game call into the OS the registers are those of the
register pin (ecx = edx = 0, eflags `0x202`, eax = 0 for void functions).

`osmap.txt` (written at quit with `istep` or `apitrace`) lists the OS-chosen values the game
holds, one per line:

```
fn <value> <IAT slot or 0> <name>   every function value it sees: IAT slot contents, GetProcAddress
                                    results, COM methods (Iface::Method). Under the oracle these are
                                    the register pin's thunks, at 0x5EA70000 + 16*i
obj <pointer> <interface>           every COM object handed to the game, in order
vtbl <pointer> <interface>          every COM vtable, in order of first use
```

The lift writes the same file with its own values (`HOST_BASE + 16*i`; its objects and vtables,
`lift/host/host.js` `writeOsmap`). Objects and vtables are named `<kind>:<interface>#<n>` by their
order per interface, so both files must list them in the order the game obtains them.

`stepdiff.py diff` reads both files (next to the captures, or `--osmap-oracle`/`--osmap-lift`).
In registers and 4-byte writes, two different values count as equal only if **both** are OS values
with the same name. A value that is an OS value on one side only is compared raw. So game data that
happens to equal a thunk or a host address is never renamed (a sprite flag `0x20000000` once
collided with the thunk area). Mismatches involving an OS value are annotated `OS-derived?`. The
oracle stream is reduced to the block starts the lift recorded; `--starts` is only cross-checked
against them, since a code map of another version would drop or add oracle entries.

Writes are predicted by decoding each instruction before it runs:
- ModRM destination operands;
- push/call/pushad/pushfd/enter;
- `stos`/`movs`, and `mov moffs`;
- setcc, shld/shrd, cmpxchg, xadd, x87 stores;
- bit-string ops. `bts`/`btr`/`btc` with a register bit offset write the operand-size unit
  holding the bit: `ea + (sext16(off) >> 4)*2` (16-bit) or `ea + (sext32(off) >> 5)*4` (32-bit).
  Before 2026-10-07 the oracle recorded 4 bytes for the 16-bit form.

Writes by OS code (`ReadFile` into a game buffer, ...) are not recorded. Two checks, which catch
different defects:
- `tools/stepdiff.py verify` finds missed writes. It applies the recorded writes to a state dump
  taken at tick A and compares the result with a dump at tick B+1. It cannot see over-recording,
  because extra bytes read back unchanged.
- `.venv/bin/python tools/stepdiff.py audit CAPTURE...` finds wrong addresses and sizes. It decodes
  every executed instruction independently (capstone), computes the addresses and sizes it writes
  from the recorded registers, and compares them with the recorded writes, per instruction form.

**Lift-side stream.** The lift emits the same file with header flags 0:
- `R` at every entry to a block that is a block start of the code map, including fall-through
  entries, with flags 0. Registers are as before the block's first instruction; eflags is
  `getEflags()`.
- `W` for every guest memory store a block performs (size 1, 2 or 4; split wider stores), in
  program order. Host-function writes are not emitted.
- `T` from the tick hook.
- `O` when dispatching to a host function: the IAT slot of the import and the return address.

`tools/stepdiff.py diff ORACLE LIFT` keeps the oracle `R` records whose eip occurs in the lift
stream (or in `--starts FILE`) and collapses rep iterations. It then walks both streams in step
and compares eips, `T` markers, registers, eflags under a mask (default `0xcd5`: CF PF AF ZF SF
DF OF), and the memory effect of each block (last write per byte). Registers an OS call leaves
undefined (ecx, edx and eflags after any `O`, and eax after a call to a `void` import) are not
compared in the block right after the call; they become the baseline and are compared again once an
instruction changes them in either stream. With the register pin they are defined anyway. It
reports the first divergence.

## Running

```
scripts/oracle-run.sh out/runs/name corpus/public/dynamite-dunes-open.txt [-- RCTHOOK_X=1 ...]
```

Results go to `out/runs/name/`: `trace.bin`, `hook.log`, `summary.txt`, `wine.log`, plus any dumps
or shots. Exit status 0 means the script reached `quit`.
