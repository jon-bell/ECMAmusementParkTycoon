# game_do_command conventions (rct.exe 1.08.183)

`game_do_command` is at `0x426F56`. `esi` = command id (handler table `0x5F49A0`, 49 entries).
Every other register is passed to the handler as is, **`ebp` included** (the dispatcher pushes and
pops it but does not change it before the handler call).

Common semantics (all commands):

- **`bl` bit 0 = apply.** The dispatcher always calls the handler once with bit 0 cleared (query /
  cost estimate), then, if the query did not fail and bit 0 was set, again to apply. The whole `bx`
  is saved in `[0x5F4A68]` while the command runs. Other flag bits seen from the game's own callers:
  `0x08` (allowed while paused), `0x10`, `0x20` (no money spent), `0x40` (ghost: the construction
  windows' previews use `bl=0x79` to place and `bl=0x29` to remove a ghost).
- **Result in `ebx`:** cost in tenths of a pound (negative for refunds), or `0x80000000` = failure.
  On failure the reason (a string id) is in `[0x991EFC]`; callers put the error title in
  `[0x991EFE]` beforehand.
- `eax`/`ecx` are not restored between the query and the apply call; outputs such as a new ride's
  index come back in `edi` (see 6, 28).
- Coordinates: `ax`, `cx` = world x, y = tile × 32. Heights: `z` registers hold height byte × 4
  (Forest Frontiers' grass is height byte 24, z `0x60`); footpath and land commands take the height
  byte itself.
- Commands can call commands (`depth` > 0 in `TR_COMMAND`), e.g. 7 demolish → 4 remove track,
  12 place entrance → 13 remove the old one, 22 raise land → 1 per tile, 25 raise water → 16,
  46 place design → 6, 3 (query) and 7.

## Evidence levels

- **UI**: captured from the game's own call when the real window was driven with `mouse` clicks
  (`TR_COMMAND` + `TR_REGS_IN*`); the run directories are under `out/cw/runs/` (not committed).
- **inj**: injected with `cmd` and accepted (result not `0x80000000`); where noted, also observed to
  have the intended effect (screenshot, the ride
  opens, guests use it, cost returned, the follow-on nested commands).
- **static**: from the handler code only (static analysis, `out/cw/static/commands.md`); not yet
  exercised. Treat as unconfirmed.

In the register column, only the fields the handler reads are listed; upper register halves the
UI happens to leave set (e.g. `eax=0xff8b0680`) are not read unless stated.

## Table

| id | meaning | registers (inputs) | evidence | caveats |
|---|---|---|---|---|
| 0 | set ride appearance | `dl` ride, `bh` field (0 track main colour, 1 track additional, 4 supports, 2/3 vehicle body/trim with `edi` = car index), `dh` colour | UI cap-ride2 (ride window colour tab: `ebx=1 edx=0x101`); inj park | `edi` unchecked for bh 2/3 |
| 1 | set land height, one tile | `ax,cx`; `dl` height byte; `dh` slope | nested (from 22/23/24, park) | not injected directly |
| 2 | toggle pause | `ebx=1` | UI (Stage 0) | |
| 3 | place track piece | `ax,cx`; `di` z (upper 16 bits of `edi` = brake/booster speed for pieces 0x63/0x64); `bh&3` direction; `dl` ride; `dh` piece; `edx` bit 16 chain lift | UI ride3 (flat ride placed by click: `eax=0x5e0 ebx=1 ecx=0x3c0 edx=0x7b00 edi=0x60`), nested from 46; inj catalogue (2,214 placements) | **the command does not check that the piece suits the ride type** (any piece < 0xAC accepted for any type; ≥ 0xAC crashes). Piece validity per type is enforced only by the construction window; corpus/gen/catalogue.py reproduces that rule. z must be a multiple of 16 (8 mod 16 for pieces with flag 0x100). |
| 4 | remove track piece | `ax,cx`; `di` z; `bh` direction; `dl` piece; `dh` sequence | nested (from 7) | static: the element search is unbounded; inject only for an existing piece |
| 5 | load / save / quit prompt | `dl`, `di` | static | **excluded**: can quit or reload |
| 6 | create ride | `dl` ride type 0..48 → new ride index in `edi` (first free slot) | UI ride2 (New Rides → Build this: `edx=0x2f`); nested from 46; inj catalogue, park | type ≥ 49 crashes; the UI offers only invented types, the command accepts any |
| 7 | demolish ride | `dl` ride | nested (from 46: `ebx=0x80000001`); inj catalogue, park | refund is negative `ebx` |
| 8 | set ride status | `dl` ride; `dh` 0 close, 1 open, 2 test | UI cap-ride (ride window lights: `edx=0x001/0x201/0x101`); inj park | open fails without a complete circuit/entrance/exit (verified: loop1) |
| 9 | set ride vehicles | `dl` ride; `bh` 0 trains, 1 cars per train, 2 vehicle type; `dh` value | UI cap-ride (`ebx=0x001 edx=0x201`, `ebx=0x101 edx=0x301`); inj park | fails on an open ride ("must be closed first") |
| 10 | rename ride | three calls: `ax`=1 chunk 0, 2 chunk 1, 0 chunk 2 + commit; text in `edx,ebp,edi` (12 bytes per chunk); commit uses `bh` = ride | inj park (all three calls succeed, cost 0); static | the UI's text window needs typed characters (WM_CHAR), which the oracle cannot inject yet |
| 11 | set ride setting | `dl` ride; `dh` 0 mode, 1 departure flags, 2 min wait, 3 max wait, 4 operation option, 5 inspection interval; `bh` value | UI cap-ride (operating tab: `ebx=0xe101 edx=0x101`, `0x601/0x201`, `0x3d01/0x301`, `0x101/0x501`); inj park | mode change needs the ride closed |
| 12 | place ride entrance / exit | `ax,cx`; `bh` direction (points from the entrance toward the station; the path joins on the opposite side); `dl` ride; `dh` 0 entrance, 1 exit; `di` station index (`0xFFFF` = a query mode) | inj loop1/park (rides open and guests use them); static | no adjacency check in the command (the window enforces it). UI capture not obtained (hover placement did not show a ghost under the oracle). |
| 13 | remove ride entrance / exit | `ax,cx`; `dl` ride; `di` station | nested (from 12) | static: unbounded search |
| 14 | remove small scenery | `ax,cx`; `bh` exact type byte; `dl` height; `edi` exact element dword | static | needs the element bytes from a map dump; unbounded search |
| 15 | place small scenery | `ax,cx`; `bh` object 0..136; `dl` quadrant | UI cap-land (scenery window: `ebx=0x1a01 edx=0`, `ebx=0x1e01 edx=0x600`); inj park | rotation is a scenario-RNG draw (or a UI global for some objects); no z input |
| 16 | set water height, one tile | `ax,cx`; `dl` water height byte | nested (from 25) | |
| 17 | place footpath | `ax,cx`; `dl` height byte; `dh` path type; `bh` slope; `di` addition | UI path2 (`eax=0x680 ecx=0x3c0 edx=0x118 ebx=1 edi=0`); inj park | |
| 18 | remove footpath | `ax,cx`; `dl` height byte | inj park (end tile of the main street); UI remove button greyed in tile mode | refunds even with no path on an owned tile |
| 19 | change surface / edge style (area) | `ax,cx` = x0,y0; `di,bp` = x1,y1; `dl` surface 0..7 or 0xFF; `dh` edge 0..7 or 0xFF | inj park (cost 0x384) | reads `ebp` |
| 20 | set ride price | `dl` ride; `dh` 0 primary, else secondary; `di` price (tenths) | UI cap-ride2 (income tab spinner: `edx=1 edi=0x33`/`0x32`); inj park | |
| 21 | rename guest / staff | three calls as 10; `ax`=1 also latches `cx` = sprite; text in `edx,ebp,edi` | inj park (returns success) | UI needs text input (see 10) |
| 22 | raise land (area) | `ax,cx` centre; `edx` = x0 \| x1<<16; `ebp` = y0 \| y1<<16; `di` selection type (4 = whole tile) | inj park (cost 0x320, nested 1) | reads `ebp`; the land tool's drag cannot be driven (see below) |
| 23 | lower land (area) | as 22 | inj park | |
| 24 | smooth raise/lower | as 22; `di` 1 raise, else lower | inj park | returns 4× the cost |
| 25 | raise water (area) | `ax,cx` = x0,y0; `di,bp` = x1,y1 | inj park (nested 16) | any failing tile fails the whole command |
| 26 | lower water (area) | as 25 | inj park | |
| 27 | set brakes speed | `ax,cx`; `di` z; `dl` piece 0x63; `bh` speed | static | query is a no-op; unbounded search |
| 28 | hire staff | `bh` type 0 handyman, 1 mechanic, 2 security, 3 entertainer; `ax,cx,dx` = x,y,z of the new peep, or `ax=0x8000` = left "picked up" (what the UI does before the player places it) → sprite index in `edi` | UI (Stage 0; cap-mgmt `ebx=0x101`); inj park (placed on a path at x*32+16, y*32+16, z 0x60: walks and works) | |
| 29 | toggle staff patrol block | `ax,cx` (4×4 block); `dx` staff sprite | UI cap-mgmt (`eax=0x4e0 ecx=0xe20 edx=0xd1`); inj park | unchecked sprite |
| 30 | fire staff | `dx` staff sprite | UI cap-land (confirmation "Yes": `edx=0x63`); inj park | |
| 31 | set staff orders / costume | `dx` sprite; `bh` order bits, or 0x80\|costume | UI cap-mgmt (`ebx=0x101 edx=0xd1`); inj park (orders; costume `bh=0x82`) | |
| 32 | rename park | three calls as 10; text in `edx,ebp,edi` | inj park | UI needs text input |
| 33 | open / close park | `dh` 1 open, 0 close | UI (Stage 0; cap-mgmt2 park window lights `edx=0x0d`/`0x10c`) | |
| 34 | land / construction rights (one tile) | `ax,cx`; `dh` 0 buy land, 1 un-own, 2 buy rights, 3 clear rights, 4/5 mark for sale | UI cap-mgmt2 (park window buy-land tool: `eax=0x4c0 ecx=0xe40 edx=0x1b`); inj park | |
| 35 | place park entrance | `ax,cx`; `dl`; `bh` | static | dead code (no caller); excluded |
| 36 | remove park entrance | `ax,cx` | static | only called from 35; excluded |
| 37 | set maze track | `ax,cx` (+ quadrant); `di` z; `dl` ride; `dh` mode; `bh` direction or 4 | nested (demolishing a maze) | |
| 38 | set park entrance fee | `di` fee (tenths) | UI cap-mgmt2 (park window price tab: `edi=0x0a`); inj park | |
| 39 | set staff uniform colour | `bh` staff type; `dh` colour | UI cap-mgmt (`ebx=1 edx=0x10a`); inj park | |
| 40 | place fence | `ax,cx`; `dl` edge; `bh` type; `dh` colour | inj park (cost 0x28) | wall-type encoding beyond what is stored is a guess |
| 41 | remove fence | `ax,cx`; `dl` edge | inj park | |
| 42 | place large scenery | `ax,cx`; `bh` direction 0..3 (≥4 crashes); `di` type 0..10; `dl,dh` colours | inj park | |
| 43 | remove large scenery | `ax,cx`; `dl` height byte | inj park (after 42) | unbounded search: only for an existing object |
| 44 | set loan | `edx` = new loan (tenths) | UI cap-mgmt (finance spinner: `edx=0x4e20`, `0x2710`); inj catalogue, park | changes cash only if the cash/loan checksum matches |
| 45 | research funding / priorities | `bh` 0 → `dl` funding level 0..3; `bh` ≠ 0 → `dl` category bitmask | UI cap-mgmt (`ebx=1 edx=1`; `ebx=0x101 edx=0x3d`); inj park | |
| 46 | place track design | `ax,cx`; `dx` z; the design itself comes from a buffer (`0x656B34`) the track-design window fills from a `.TD4` file, rotation from a UI global | UI coaster2/3 (`eax=0x6a0 ecx=0x360 edx=0x60 edi=0x60`) | not injectable on its own |
| 47 | start marketing campaign | `dl` campaign 0..5; `bh` weeks; `dh` target ride/item | UI cap-land (finance marketing → Start: `ebx=0x201 edx=0xff00`); inj park | cost charged on the query too |
| 48 | place maze tile with walls | `ax,cx`; `di` z; `dl` ride; `bh \| dh<<8` wall mask | inj catalogue (maze) | only the maze-design placer calls it |

## What the oracle cannot drive yet (requests in out/status/corpus.md)

- Text entry (rename windows) arrives as `WM_CHAR`, which the oracle drops: 10, 21, 32 via UI.
- Click-and-drag tools (land, water, surface painting): the drag did not register; the button
  state seems to come from DirectInput or messages the oracle does not feed. 19, 22–26 were
  confirmed by injection only.
- File > Load/Save uses the common dialogs `GetOpenFileNameA`/`GetSaveFileNameA` (modal, unpinned).
