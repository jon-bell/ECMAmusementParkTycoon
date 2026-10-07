# Input corpus

Each file is an oracle input script (format: `oracle/README.md`). A case is identified by its
path. Scenario numbers are the game's own (`Scenarios/SC<n>.SC4`); 0–4 are the scenarios the
shipped game unlocks at first start (Forest Frontiers, Dynamite Dunes, Leafy Lake, Diamond
Heights, Evergreen Gardens).

- `public/`  cases that porting work may run, read and debug against.
- `heldout/` cases that porting work never sees (principle 7). The determinism gate runs them
  because they test the oracle, not a port; a port is scored on them only at acceptance.
- `gen/`     the generators that wrote the generated cases (`gen/make_cases.py` rewrites them all).
- `COMMANDS.md` the `game_do_command` conventions the cases rely on, with their evidence.

`seed` sets the virtual clock at process start. The scenario RNG seed is
`timeGetTime() ^ srand0` at the moment the scenario starts (0x43054E), so distinct seeds give
distinct parks from the same scenario.

## Cases

| family | public | held-out | what it exercises |
|---|---|---|---|
| Stage 0 | title, diamond-heights-pause, dynamite-dunes-open, forest-frontiers-open | diamond-heights-seed2, evergreen-gardens-open, leafy-lake-open | intro and title park; scenarios 0–4 left as loaded or opened; pause; hiring |
| `tour-scNN-*` | 14 scenarios | 7 scenarios | every shipped scenario 0–20: open the park, then view the whole map at 1:4 from all four rotations (`gen/tour.py`: toolbar zoom/rotate clicks, arrow-key scrolling in a raster from the top-left clamp). Paints every ride, scenery item and guest the scenario contains; ~10.7k ticks of simulation |
| `catalogue-*` | 6 (every ride type, pieces in direction 0) | 3 (every ride type, random directions, other groupings and seeds) | for every ride type 0–48, every track piece the construction window offers for it, built in Forest Frontiers with `cmd 6/3/7` and viewed at 1:4, 1:2, 1:1 in four rotations (`gen/catalogue.py`). Covers the per-ride-type piece painters, most of CODESEG |
| `viewopts-*` | sc07 | sc15 | View-menu options (underground, see-through, invisible supports/people, gridlines, height marks) with local tours |
| `uitour-*` | sc03 | sc15 | the game's windows by clicks: every ride window tab, guest/staff windows, finances, research, park, map, messages, scenery/land/path/new-ride windows (`gen/uitour.py`) |
| `park-ff-*` | build | variant | a working park built with commands in Forest Frontiers (paths, flat rides, stalls, a car-ride circuit, entrances/exits, staff on the paths, prices, fee, research, marketing, landscaping, land purchase, rename), opened and run ~2 months with mid-run changes (`gen/park.py`) |

Split: the Stage 0 cases keep their split. Tours are assigned by `gen/split.py` (random, recorded
seed 20261006, one third held out). The catalogue, viewopts, uitour and park families are split by
design: held-out cases repeat the public case's kind of input on other data (other scenario,
other seed, other directions/placement), so that a gap between public and held-out results
points at the port, not at code only one side reaches. Held-out cases must not be the source of
any porting decision.

## Regenerating

```
python3 corpus/gen/make_cases.py          # rewrites every generated case
```

The catalogue needs two inputs that are not committed (they derive from the user's game):
`game/cd/English/rct.exe` (tables read at generation time by `gen/rctexe.py`) and the
construction window's piece-selector map, produced by a discovery run:

```
python3 corpus/gen/catalogue.py probe-script out/corpus/selector-probe.txt
scripts/oracle-run.sh out/corpus/selector-probe out/corpus/selector-probe.txt
python3 corpus/gen/catalogue.py probe-parse out/corpus/selector-probe/trace.bin
```

The discovery run uses `poke` and `call` (allowed for discovery, never in a corpus case).

## Coverage (second instrument)

`tools/coverage.py` reports instruction-weighted coverage from runs with
`RCTHOOK_SPIKE=cover=<Windows path of out/spikes/s1/blocks-all.bin>` (one-shot breakpoint per
block of the static map v2). Current numbers and their history: `out/status/corpus.md`.

## Decisions that need a human (principle 8)

1. **Locked scenarios 5–20 are in the corpus.** The UI greys them out until earlier scenarios are
   completed, but `load N` reaches them through the same new-game routine (0x43054E) the
   scenario window uses. They are included because they hold most of the shipped rides.
2. **Ride types that the scenario has not invented.** The catalogue creates every ride type 0–48
   in Forest Frontiers; the New Rides window offers only invented types (the command accepts any).
   The track pieces are restricted to those the construction window would offer for the type
   with the feature bits seen at the start of any shipped scenario (static table 0x5F5594 plus
   research bits); `gen/catalogue.py` documents the rule.
3. **Scripted UI clicks and keys in corpus cases.** Tours, view options and the UI tour use the
   game's own mouse queue and arrow keys (not raw OS input) to reach rendering and window code.
   They are game-coordinate clicks on fixed layouts, so a change in window placement would make
   them click elsewhere (deterministically).
4. **Commands not used in any case:** 5 (load/save/quit prompt), 13 (only nested, from 12 replacing an entrance; seen in discovery), 46 (needs the track-design window), 35/36 (park entrance; dead
   code), 14 (needs exact element bytes), 27 (needs a brake piece). COMMANDS.md gives the
   evidence for each; 5, 14, 27, 35, 36 are static-only.
5. **Multi-tick frames (`RCTHOOK_QUANTUM`)** are not in the corpus: the gate has no per-case
   environment (requested from the oracle workstream as a script directive). Measured value: a
   quantum of 40 gives three ticks per frame and reaches code a one-tick run does not.
6. **Saved games** are not in the corpus: the CD has no saved games (only a 3-byte placeholder
   `Saved Games/001`), and File > Load/Save use unpinned common dialogs (requested).

7. **Rejected inputs are kept.** The catalogue's boat-hire pieces are rejected by the game (no
   water under them); the commands stay in the cases because the rejection path is binary
   behaviour too.
8. **Three cases fail the gate's layout-shift check** (uitour-sc03, uitour-sc15, tour-sc17)
   because two drawing-context pointers (0x99FE08, 0x9A012C) are missing from the oracle's mask
   (`oracle/mask.h`); both clean runs agree on every case. The cases are kept as the evidence;
   the fix belongs in the mask (requested, `out/status/corpus.md`).

## Cost

Oracle CPU time per gate run of the corpus (each case runs twice plus once layout-shifted): about
1.8 oracle CPU-hours (12 minutes wall at 12 parallel runs); details in
`out/status/corpus.md`. Single runs: tours ~100 s, catalogue 15–35 s, viewopts/uitour ~60 s,
park ~5 min, Stage 0 cases 25–40 s.
