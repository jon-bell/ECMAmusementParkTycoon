# What Wine answers: the host's specification for unpinned OS behaviour

The lift's host implements the Win32 and COM functions rct.exe calls (`docs/stage1-design.md`).
Where the oracle pins an answer (`oracle/README.md`, "Pins"), the host reproduces the pin. This
document covers everything else: the answers Wine gives that no pin fixes. For each it gives the
value, whether it was the same in every corpus case and run, and whether it reaches game state.
The host reproduces these values as documented constants, or as the documented behaviour. It never
reads oracle data at run time (principle 7).

Values are as the game sees them, through the oracle's pins. Hex is without `0x` in the tables.

## How this was measured

- **API traces** (`RCTHOOK_SPIKE=apitrace`, `oracle/README.md` "API trace"): every call the game
  makes, with arguments, results and out-params, and every callback into game code.
  - Runs: all 43 corpus cases (`corpus/public`, `corpus/heldout`), once each (`out/oi/at4/*-r0`).
    Five cases were run twice more: a second clean run with a different environment size and run
    directory (`-r1`), and a layout-shifted run (`-shift`, `heapshift=200003`, which moves the
    heap, mappings and kernel, USER and GDI handle numbers).
  - **Stable** means every case shows the same value at the same call site. Run-to-run and layout
    stability is the `tools/apitrace.py diff` of the r0, r1 and shift traces; see "Stability" at
    the end.
- **Reaches game state** was measured by perturbation (`RCTHOOK_PERTURB`, `oracle/README.md`).
  - The run XORs the answer the game receives. The reference is an unperturbed traced run of
    `corpus/public/forest-frontiers-open` (4,000 ticks, a park opened and a handyman hired).
  - **yes** means the masked state hash (`TR_MSTATE`) differs. **no** means RNG, masked and raw
    state are identical over all 4,000 ticks.
  - A **no** holds only for this case and this perturbation. The answer may matter in code the
    case does not reach.
  - Results: `out/oi/pt-results.txt`.
- **Stale bytes.** Several structures contain bytes the callee does not write. The trace shows
  them as `..` or `-` (`oracle/README.md`), and the host need not reproduce them.
- Environment: Wine 9.0 (Ubuntu noble), 32-bit prefix, Xvfb 1024×768×24, no audio device, no
  window manager. A different Wine build or machine can change any value below; the entries
  marked *machine* depend on the CPU the oracle runs on.

## Summary

| Function | Answer | Stable | Reaches state |
|---|---|---|---|
| process entry | `esp=31FF54`, `eax=ebx=3FFF1000`, `edx=412E80`, `ebp=31FF68`, `ecx=esi=edi=0`, eflags `246`; `[esp]=7BBB8B00` | yes | (entry state) |
| `GetVersion` | `23F00206` (Windows "6.2", build `23F0`, NT) | yes | no |
| `GetVersionExA` | 1; size 94, major 6, minor 2, build `23F0`, platform 2, CSD "" | yes | no |
| `GetSystemInfo` | arch 0, page 1000, min `10000`, max `7FFEFFFF`, active mask `FFFFFFFF`, **nproc C8 (200)**, type `24A` (586), granularity `10000`, level `17`, revision `3100` | yes *machine* | no |
| `IsProcessorFeaturePresent(0)` (via GetProcAddress) | 0 | yes | not perturbed |
| `GetSystemMetrics` | 0→`400`, 1→`300`, `22`→`7B`, `23`→`22`, `20`→4, `21`→4, 4→`1A`, `17`→0 | yes | **yes** (from tick 1) |
| `GetDeviceCaps` (DC `B010044`) | `C` BITSPIXEL→`20`, `26` RASTERCAPS→`BE99`, `68` SIZEPALETTE→0, `6C` COLORRES→`18`, `6A` NUMRESERVED→`14`, `18` NUMCOLORS→`FFFFFFFF` | yes | no |
| `SystemParametersInfoA(3 SPI_GETMOUSE)` | 1; {6, 10, 1} | yes | no |
| `GetKeyboardType` | 0→4, 1→0, 2→`C` | yes | no |
| `GetACP` / `GetCPInfo(4E4)` | `4E4` / 1, MaxCharSize 1, DefaultChar `3F 00`, no lead bytes | yes | no |
| `LCMapStringW`, `GetStringTypeW`, `MultiByteToWideChar`, `WideCharToMultiByte` | C runtime ctype/locale tables, cp1252 (hashes in the traces) | yes | `LCMapStringW` ret: no |
| `GetStartupInfoA` | cb 44, desktop "", title = path of rct.exe, flags 0, show 0, std handles `FFFFFFFF` | content yes; the two string pointers vary with the environment | no |
| `GetStdHandle` / `GetFileType` | `FFFFFFF6`→8 (type 2 char), `FFFFFFF5`→`C` (1 disk), `FFFFFFF4`→`10` (1 disk) | yes | no |
| `SetHandleCount(20)`, `SetErrorMode(0)` | `20`, 0 | yes | n/a |
| `GetCommandLineA` | `"C:\Program Files\Hasbro Interactive\RollerCoaster Tycoon\rct.exe"` with quotes | content yes; pointer varies | not perturbed |
| `GetModuleFileNameA(0)` | 40, `C:\Program Files\Hasbro Interactive\RollerCoaster Tycoon\rct.exe` (into `.data` `5EFF10`) | yes | no |
| `GetModuleHandleA` | NULL→`400000`, "KERNEL32"→`7BB90000` | yes | n/a |
| `LoadLibraryA("DDRAW.DLL")` | `76D50000` (varies with the oracle build: Wine places DLLs) | per build | no (not in state) |
| `HeapCreate(1,1000,0)` | `1A20000` (`1920000` in other runs) | layout | masked/irrelevant (heap) |
| `VirtualAlloc` | `0,400000,MEM_RESERVE` → `2E70000`; commit `10000` there | layout | heap |
| `CreateFileMappingA` / `MapViewOfFile` (CSG1.DAT) | handle `D8`; view `3CA0000` (`3C80000` in earlier runs) | layout | masked (`mask.h`) |
| `CreateDIBSection` 1024×−768×8 | HBITMAP `3090085`; bits `52E0000` | layout | bits masked |
| `CreateFileA` handles | `D4` for every file, since each is closed before the next opens; `C8`/`CC` registry keys | yes | `5F88A4` masked |
| `ReadFile`, `SetFilePointer` | byte counts and positions of the user's own files | yes (the files) | yes: file data |
| `RegOpenKeyA`/`RegQueryValueExA` | see "Registry" | yes | **yes**: written into DATASEG |
| `OpenMutexA`/`CreateMutexA("RollerCoaster Tycoon_GSKMUTEX")` | 0 (not found) / `CC` | yes | n/a |
| `RegisterClassA` | atom `C043` | yes | n/a |
| `LoadIconA`, `LoadCursorA` (22 game cursors, IDC_ARROW) | `30056`; `4005C`, `20060`, `10062`…`10088`; IDC_ARROW `1004A` | yes | **yes**: cursor table `9A1550`, masked |
| `GetStockObject(4)` | `1900024` | yes | no |
| `CreateFontIndirectA` (MS Sans Serif 12) | `110A005C` | yes | n/a |
| `CreatePalette`, `CreateCompatibleDC`, `CreateRectRgn` | `…`, `5C41005F`, `7040083` | yes | n/a |
| `CreateWindowExA` | HWND `1008A` | yes | n/a (in `.data`) |
| `CreateDialogParamA(#101)` | HWND `100A0`; `GetDlgItem(3E8)` → `100AC` | yes | n/a |
| `GetSystemPaletteUse` | 1 (SYSPAL_STATIC) | yes | n/a |
| `GetUpdateRect` / `GetUpdateRgn` | 1, {0,0,280,1E0} / 2 (SIMPLEREGION) | yes | no |
| `IsWindow(0)` | 0 | yes | no |
| `RealizePalette`, `SelectPalette`, `StretchDIBits`, `AnimatePalette` | per call; see traces | yes | `RealizePalette`, `StretchDIBits`, `SelectPalette` ret: no |
| `GetDC`/`ReleaseDC` | DC `B010044` (cached); `ReleaseDC` 1 | yes | n/a |
| `DirectDrawCreate` (via GetProcAddress) | `S_OK`, IDirectDraw `176AE74` | layout | n/a |
| `IDirectDraw::EnumDisplayModes` | **one mode**: 1024×768, 32 bpp, pitch `1000`, RGB masks `FF0000/FF00/FF`, flags `4100E` | yes | selects the windowed path |
| `mciSendStringA("close all")` | 0, return string not written | yes | no |
| `midiOutGetNumDevs` / `GetDevCapsA(FFFFFFFF)` / `GetVolume(FFFFFFFF)` | 0 / 2 (BADDEVICEID, struct not written) / 0, `FFFFFFFF` | yes | no |
| `timeBeginPeriod(1)` | 0 | yes | n/a |
| `DirectSoundEnumerateA` | pinned: returns 0 without calling back | | |
| window and dialog messages | see "Messages": all at start-up | yes | via the window procedure's `.data` |
| `DefWindowProcA` | per message, see traces | yes | yes (perturbing it breaks start-up) |

"n/a" means not perturbed: a handle the game only passes back to the OS. Its value matters only
if it lands in game state, and the mask audit covers that (`docs/stage1-scope.md` M5 addendum).

## Process start

- The entry point `0x412E80` is entered with `esp = 0x31FF54`, `ebp = 0x31FF68`,
  `eax = ebx = 0x3FFF1000` (the PEB), `ecx = esi = edi = 0`, `edx = 0x412E80` and eflags `0x246`.
  The stack holds a return address into kernel32 (`0x7BBB8B00`), then `0x3FFF1000`, `0x7BD644F3`,
  `0x7BD644F3`.
- The main thread's stack is `[0x220000, 0x320000)`. The C runtime then calls `GetVersion`,
  `HeapCreate`, two `VirtualAlloc`s, `GetStartupInfoA`, the three std handles, `GetACP`, the
  `GetCPInfo`/`MultiByteToWideChar`/`LCMapStringW`/`GetStringTypeW` table builds,
  `GetCommandLineA`, `GetEnvironmentStringsW` (pinned) and `GetModuleFileNameA`.

## Registry (`HKLM\Software\Fish Technology Group\RollerCoaster Tycoon Setup`, from the install)

| Value | Type | Answer | Written to |
|---|---|---|---|
| CDKey (key handle `C8`) | 4 | 0 | stack |
| Title | 1 | "Rol" (4 bytes, as installed) | DATASEG `5F8544` |
| Path | 1 | `C:\Program Files\Hasbro Interactive\RollerCoaster Tycoon` (39 bytes) | DATASEG `5F8648` |
| SetupPath | 1 | `D:\` | DATASEG `5F874C` |
| InstallLevel | 4 | 1 | DATASEG `5F8540` |
| FontPointSize | 4 | 12 | stack → `CreateFontIndirectA` |
| FontFaceName | 1 | "MS Sans Serif" | stack |
| CharSet | 4 | 0 | stack |
| OKPrompt, CancelPrompt | 1 | "OK", "Cancel" | `.data` `5E91F0`, `5E92F8` |

`HKU\.DEFAULT\Software\Microsoft\MS Setup (ACME)\User Info` does not exist: `RegOpenKeyA`
returns 2. The `RegQueryValueExA` buffers point straight into DATASEG, so these strings are game
state.

## Messages: the complete sequence delivered to game code

Every window-procedure (`0x403D79`) and dialog-procedure (`0x4037CF`, dialog #101) entry happens
during start-up, in frame 1. It is the same in every case. In no case does a message reach game
code after start-up: the input pin drops mouse and keyboard messages (`# drop` lines in the
trace), and nothing else is sent.

1. Inside `CreateWindowExA` (main window, `1008A`):
   `WM_GETMINMAXINFO`, `WM_NCCREATE`, `WM_NCCALCSIZE`, `WM_CREATE`, `WM_SHOWWINDOW`,
   `WM_WINDOWPOSCHANGING`, `WM_GETICON` (×2), `WM_QUERYNEWPALETTE`, `WM_PALETTEISCHANGING`,
   `WM_ACTIVATEAPP`, `WM_NCACTIVATE`, `WM_ACTIVATE`, `WM_IME_SETCONTEXT`, `WM_SETFOCUS`,
   `WM_NCPAINT`, `WM_ERASEBKGND`, `WM_WINDOWPOSCHANGED`, `WM_SIZE (1E00280)`,
   `WM_MOVE (3E0024)`.
2. Inside `CreateDialogParamA(#101)`: dialog `WM_SETFONT`, window `WM_IME_NOTIFY` ×2, dialog
   `WM_INITDIALOG`.
   - Nested in it: `SendMessageA` → `WM_SETFONT`; `SendDlgItemMessageA` → window
     `WM_IME_NOTIFY`; `SetWindowTextA` → `WM_SETTEXT ""`.
   - `SetFocus` → window `WM_NCACTIVATE`, `WM_ACTIVATE`, `WM_KILLFOCUS`, `WM_IME_SETCONTEXT`;
     dialog `WM_QUERYNEWPALETTE`, `WM_NCACTIVATE`, `WM_ACTIVATE`, `WM_COMMAND`.
   - Then dialog `WM_SHOWWINDOW`, `WM_WINDOWPOSCHANGING`, `WM_GETICON` ×2, `WM_NCPAINT`,
     `WM_ERASEBKGND`, `WM_CTLCOLORDLG`, `WM_WINDOWPOSCHANGED`.
3. `SendMessageA(dialog, WM_COMMAND, 2)`.
4. Inside `DestroyWindow(dialog)`: dialog `WM_WINDOWPOSCHANGING`/`CHANGED`, `WM_NCACTIVATE`,
   `WM_ACTIVATE`; window `WM_QUERYNEWPALETTE`, `WM_PALETTECHANGED` (dialog and window),
   `WM_NCACTIVATE`, `WM_ACTIVATE`; dialog `WM_COMMAND`; window `WM_IME_SETCONTEXT`,
   `WM_SETFOCUS`; dialog `WM_DESTROY`, `WM_NCDESTROY`.
5. `DispatchMessageA` → `WM_PAINT`; then `PeekMessageA` delivers `WM_NCHITTEST`
   (lParam `1800200`: screen (512, 384), Xvfb's pointer) to the window procedure.

The exact order and every argument are in each trace (`apitrace.py dump --grep 'wndproc|dlgproc'`).
The structures passed with messages (MINMAXINFO, CREATESTRUCT, WINDOWPOS, NCCALCSIZE_PARAMS) are
recorded in full, before and after the game's procedure.

## DirectX

- `DirectDrawCreate` succeeds. `EnumDisplayModes` is called three times (`0x408BF9`, `0x408D42`,
  `0x4060E4`); each time Wine reports exactly one mode, the desktop's 1024×768×32. None is 8-bit,
  so the game takes its windowed GDI path (DIB section, `StretchDIBits`). No surface, palette or
  clipper is ever created.
- DirectSound: pinned (`DSERR_NODRIVER`). DirectInput: pinned (fake devices). Their
  `SetDataFormat` calls pass `c_dfDIMouse` (7 objects, 16 bytes) and `c_dfDIKeyboard`
  (256 objects, 256 bytes) from the game's image.

## Cursor and screen coordinates

`GetCursorPos` is called once, at `0x40590B` from the frame function's initialisation. It
returns the virtual cursor (1000, 740) and lands in DATASEG `0x628CD0`/`0x628CD4` (perturbation:
yes). The hover position comes from `WM_MOUSEMOVE` only, and the click queue from button
messages. Both are pinned (`oracle/README.md`).

## Stale and undefined bytes the host need not reproduce

- `midiOutGetDevCapsA` fails and leaves its MIDIOUTCAPSA untouched.
- `GetVersionExA`'s input structure, apart from its size, is uninitialised stack.
- `CPINFO`'s 2 padding bytes.
- Bytes after the NUL in `WIN32_FIND_DATAA` names. These keep the game's previous contents, and
  the game reads them back into DATASEG `0x5F9313`: the host writes only up to the NUL, as the
  oracle's `put_find` does.
- `mciSendStringA`'s return buffer (NULL here).

## Pins added in Stage 1 because API traces showed run-to-run variation

`GetEnvironmentStrings(W)` (a fixed block), `PeekMessageA`'s `MSG.time` and `MSG.pt`, the search
handle of `FindFirstFileA`, and the common file dialogs. See `oracle/README.md`.

## Stability

Pending the completed batch.

## Regenerating

```
scripts/oracle-run.sh out/x <case> -- RCTHOOK_SPIKE=apitrace
python3 tools/apitrace.py shapes out/*/apitrace.txt --name 'GetSystemMetrics|GetDeviceCaps'
python3 tools/apitrace.py dump out/x/apitrace.txt --grep 'wndproc|dlgproc'
scripts/oracle-run.sh out/p corpus/public/forest-frontiers-open.txt -- RCTHOOK_SPIKE=apitrace \
    'RCTHOOK_PERTURB=GetSystemMetrics:ret^0x10'
python3 tools/rcttrace.py compare out/ref/trace.bin out/p/trace.bin masked
```
