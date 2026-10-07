#!/usr/bin/env python3
"""Ride catalogue: build every ride type's track pieces in Forest Frontiers and look at them.

Most of CODESEG is the ride painters: one jump table of piece painters per ride type (table of
tables at 0x5F6274, 49 ride types), each painting a piece in 4 directions. The scenario tours paint
only the pieces that the shipped parks happen to contain. This generator builds, for each ride
type, every track piece the game's construction window would offer for that type, as separate
unconnected pieces on open land, then views them at three zoom levels in all four rotations
(painter direction = piece direction + view rotation, so one placement covers 4 directions), and
demolishes the ride (refund) before the next batch.

Inputs are game commands (oracle/README.md `cmd`; conventions in corpus/COMMANDS.md):
  cmd 44  set loan (to the scenario's maximum, so the batches can be paid for)
  cmd 6   create ride (dl = ride type); the new ride gets index 0 (Forest Frontiers has no rides)
  cmd 3   place track piece (ax,cx = x,y; di = z; bh = direction; dl = ride; dh = piece)
  cmd 7   demolish ride
plus toolbar clicks for zoom and rotation.

Which pieces "the construction window would offer" (principle: inputs a player could give):
  - ordinary pieces: the image of the window's piece selector (0x5D298A) over every construction
    state (curve, slope pair, bank pair, diagonal) whose buttons the type's track-feature word
    enables. The selector map comes from a discovery run (`probe-script`/`probe-parse`), which
    calls 0x5D298A with the state globals set; the enables are those of the construction window
    (0x5D13E2, 0x5D08D8): curve code 0 needs feature bit 1, codes 1-2 bit 0x10, 3-4 bit 0xF,
    5-6 bit 0xE, 7-8 and diagonal directions ride-type flag bit 30; gentle/steep/vertical slopes
    bits 8/9/0x1C; curves while sloped bits 0xB (gentle) / 0xC (steep); banking bit 6.
  - special pieces (the window's dropdown, 0x5D13E2): byte s = [0x6545AF + 8p]; allowed if s has
    bit 7 and s&0x7F == type, or if bit s of the feature word is set.
  - the feature word is the static table 0x5F5594[type] plus research bits: FEATURE_RESEARCH
    below is the union of the extra bits found at tick 2 in the 21 shipped scenarios (dumps).
  - flat rides and stalls: the one piece the window places for the type ([0x5F598E + 4*type]).
HUMAN DECISION: ride types are created whether or not the scenario has invented them (the
command accepts any type 0..48; the New Rides window offers only invented ones). Forest Frontiers
is used because it is the only shipped park with a large free flat area.

  catalogue.py probe-script OUT.txt          discovery script for the selector map
  catalogue.py probe-parse TRACE MAP.json    selector map from the discovery run's trace
  catalogue.py case TYPES [--map MAP.json]   print a case script for the given ride types
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from rctexe import Exe  # noqa: E402

DEFAULT_MAP = os.path.join(ROOT, 'out', 'corpus', 'selector_map.json')

# selector state globals (construction window)
G = {'curve': 0x652294, 's0': 0x65229A, 's1': 0x652295, 'b0': 0x652299, 'b1': 0x652296, 'dir': 0x652290}
SLOPES = (0, 2, 4, 6, 8, 0xA, 0x12)
BANKS = (0, 2, 4, 0xF)
GENTLE, STEEP, VERTICAL = {2, 6}, {4, 8}, {0xA, 0x12}

# extra track-feature bits present at scenario start in some shipped scenario (type: bits)
FEATURE_RESEARCH = {0: 0x8000000, 1: 0x40080, 3: 0xE0080, 15: 0x80, 19: 0xC0080}

# Forest Frontiers: free, owned, flat grass at height byte 24 (z 96), no scenery: tiles
# x 47..62, y 32..47 (found from a state dump: surface element only, ownership bit 0x20, slope 0)
AREA = (47, 32, 62, 47)
GROUND_Z = 96
SCENARIO, MAX_LOAN = 0, 300000

ZOOM_OUT, ZOOM_IN, ROTATE = (117, 14), (146, 14), (180, 14)
OBJECTIVE_CLOSE = (427, 156)


# ------------------------------------------------------------------ selector discovery
def probe_states():
    for curve in range(9):
        for s0 in SLOPES:
            for s1 in SLOPES:
                for b0 in BANKS:
                    for b1 in BANKS:
                        for d in (0, 4):
                            yield {'curve': curve, 's0': s0, 's1': s1, 'b0': b0, 'b1': b1, 'dir': d}


def probe_script(out):
    """Discovery only (never a corpus case): poke the window's state globals and call the
    selector. The globals are all 0 at tick 4 of Forest Frontiers (checked in a dump)."""
    cur = {k: 0 for k in G}
    L = ['# selector discovery (corpus/gen/catalogue.py probe-script); not a corpus case',
         'seed 7000000', 'frame 1 load 0', 'tick 3 cmd 6 ebx=1 edx=0']
    for st in probe_states():
        for k, v in st.items():
            if cur[k] != v:
                L.append(f'tick 4 poke {G[k]:#x} {cur[k] ^ v:#x}')
                cur[k] = v
        L.append('tick 4 call 0x5d298a')
    L.append('tick 6 quit')
    open(out, 'w').write('\n'.join(L) + '\n')


def probe_parse(trace, out):
    sys.path.insert(0, os.path.join(ROOT, 'tools'))
    import rcttrace as T
    recs = T.load(trace)
    res = []
    for k, r in enumerate(recs):
        if r[0] == T.K['TR_INJECT'] and r[2] == 0x5D298A:
            j = k
            while recs[j][0] != T.K['TR_REGS_OUT2']:
                j += 1
            edx = recs[j][1]
            while recs[j][0] != T.K['TR_REGS_OUT3']:
                j += 1
            res.append(None if recs[j][2] & 1 else (edx >> 8) & 0xFF)
    states = list(probe_states())
    assert len(res) == len(states), (len(res), len(states))
    m = [dict(st, piece=p) for st, p in zip(states, res) if p is not None]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(m, open(out, 'w'))
    print(f'{len(m)} states map to {len(set(x["piece"] for x in m))} pieces -> {out}')


# ------------------------------------------------------------------ allowed pieces
def features(exe, t):
    return exe.u32(0x5F5594 + 4 * t) | FEATURE_RESEARCH.get(t, 0)


def ride_flags(exe, t):
    return exe.u32(0x5F5B78 + 8 * t)


def state_enabled(st, F, flags):
    bit = lambda b: (F >> b) & 1  # noqa: E731
    c = st['curve']
    need = {0: 1, 1: 0x10, 2: 0x10, 3: 0xF, 4: 0xF, 5: 0xE, 6: 0xE}
    if c in need:
        if not bit(need[c]):
            return False
    elif not (flags >> 30) & 1:
        return False
    if st['dir'] >= 4 and not (flags >> 30) & 1:
        return False
    slopes = {st['s0'], st['s1']}
    if slopes & GENTLE and not bit(8):
        return False
    if slopes & STEEP and not bit(9):
        return False
    if slopes & VERTICAL and not bit(0x1C):
        return False
    if c and slopes & GENTLE and not bit(0xB):
        return False
    if c and slopes & (STEEP | VERTICAL) and not bit(0xC):
        return False
    if 0xF in (st['b0'], st['b1']):
        return False
    if (st['b0'] or st['b1']) and not bit(6):
        return False
    return True


def allowed_pieces(exe, t, smap):
    flat = exe.u8(0x5F598E + 4 * t)
    flags = ride_flags(exe, t)
    if flat != 1:                       # flat ride, stall, tower base, maze: the one piece
        return [flat]
    F = features(exe, t)
    ps = {x['piece'] for x in smap if state_enabled(x, F, flags)}
    for p in range(0xAC):
        s = exe.u8(0x6545AF + 8 * p)
        if s == 0:
            continue
        if s & 0x80:
            if (s & 0x7F) == t:
                ps.add(p)
        elif (F >> s) & 1:
            ps.add(p)
    return sorted(ps)


def blocks(exe, p, d=0):
    """Tiles (dx, dy) and z offsets of piece p in direction d (cmd 3's block walk, 0x5CF1BB)."""
    a = exe.u32(0x652498 + 4 * p)
    out = []
    while exe.u8(a) != 0xFF:
        x, y, z = exe.s16(a + 1), exe.s16(a + 3), exe.s16(a + 5)
        for _ in range(d):
            x, y = y, -x
        out.append((x // 32, y // 32, z))
        a += 10
    return out


def z_for(exe, p):
    zs = [b[2] for b in blocks(exe, p)]
    z = GROUND_Z + 32 + max(0, -min(zs))
    z = (z + 15) // 16 * 16
    if exe.u16(0x652309 + 2 * p) & 0x100:     # pieces whose z must be 8 mod 16
        z += 8
    return z


# ------------------------------------------------------------------ layout
class Packer:
    def __init__(self, area):
        self.x0, self.y0, self.x1, self.y1 = area
        self.used = set()

    def place(self, tiles):
        """Origin (tx, ty) such that every tile and a one-tile margin around it is free."""
        for ty in range(self.y0, self.y1 + 1):
            for tx in range(self.x0, self.x1 + 1):
                abs_t = [(tx + dx, ty + dy) for dx, dy in tiles]
                if not all(self.x0 <= x <= self.x1 and self.y0 <= y <= self.y1 for x, y in abs_t):
                    continue
                ring = {(x + i, y + j) for x, y in abs_t for i in (-1, 0, 1) for j in (-1, 0, 1)}
                if ring & self.used:
                    continue
                self.used |= set(abs_t)
                return tx, ty
        return None


class Script:
    def __init__(self):
        self.L = []
        self.tick = 1          # commands go at tick boundaries
        self.frame = 20        # clicks at frames after the load

    def click(self, xy, wait=6):
        self.L.append(f'frame +{self.frame} mouse {xy[0]} {xy[1]} 1')
        self.L.append(f'frame +{self.frame + 2} mouse {xy[0]} {xy[1]} 3')
        self.frame += wait

    def cmd(self, line):
        self.L.append(f'tick {self.tick} {line}')

    def sync(self):
        """Ticks and frames advance together (one tick per frame); keep both in order."""
        self.tick = max(self.tick, self.frame) + 1
        self.frame = self.tick + 1


def view(s):
    """1:1 -> 1:4 -> 1:2 -> 1:1, four rotations at each level, a few frames per rotation."""
    s.click(ZOOM_OUT, 4)
    s.click(ZOOM_OUT, 4)
    for _ in range(4):
        s.click(ROTATE, 6)
    s.click(ZOOM_IN, 4)
    for _ in range(4):
        s.click(ROTATE, 6)
    s.click(ZOOM_IN, 4)
    for _ in range(4):
        s.click(ROTATE, 6)


def piece_jobs(t, smap, exe):
    """(piece, z) placements for ride type t, in the order they are built."""
    flat = exe.u8(0x5F598E + 4 * t)
    if flat == 0x65:                          # hedge maze: built tile by tile with cmd 48
        return []
    if flat != 1:                             # flat ride, stall, tower base: on the ground
        jobs = [(flat, GROUND_Z)]
        F = features(exe, t)
        if flat == 0x42 and (F >> 0x14) & 1:  # tower: sections stacked on the base
            jobs += [(0x43, GROUND_Z + 0x60 + 0x20 * k) for k in range(8)]   # on the 0x60-high base
        return jobs
    return [(p, z_for(exe, p)) for p in allowed_pieces(exe, t, smap)]


def case(types, smap, exe, seed=7300000, dirs=None, area=AREA):
    """dirs: None = every piece in direction 0; a random.Random = random direction per piece."""
    s = Script()
    L = s.L
    L += [f'seed {seed}', f'frame 1 load {SCENARIO}',
          f'frame +10 mouse {OBJECTIVE_CLOSE[0]} {OBJECTIVE_CLOSE[1]} 1',
          f'frame +12 mouse {OBJECTIVE_CLOSE[0]} {OBJECTIVE_CLOSE[1]} 3']
    s.tick = 2
    s.cmd(f'cmd 44 ebx=1 edx={MAX_LOAN:#x}                # SET_LOAN to the maximum')
    s.frame = 20
    s.sync()
    total = 0
    # tracked types one ride at a time; all flat rides / stalls / towers / mazes in shared batches
    tracked = [t for t in types if exe.u8(0x5F598E + 4 * t) == 1]
    flats = [t for t in types if t not in tracked]
    queue = [[(t, j) for j in piece_jobs(t, smap, exe)] for t in tracked]
    if flats:
        queue.append([(t, j) for t in flats for j in (piece_jobs(t, smap, exe) or [('maze', 0)])])
    for jobs in queue:
        batch = 0
        while jobs:
            pk = Packer(area)
            rides, placed, rest = {}, [], []
            for t, job in jobs:
                d = dirs.randrange(4) if dirs else 0
                if job[0] == 'maze':
                    o = pk.place([(x, y) for x in range(4) for y in range(4)])
                elif job[0] == 0x43:                   # tower sections go on top of the tower base
                    o = 'stack'
                else:
                    o = pk.place([(b[0], b[1]) for b in blocks(exe, job[0], d)])
                (placed if o else rest).append((t, job, d, o))
            if not placed:
                L.append(f'# {len(rest)} placements do not fit the area; skipped')
                break
            L.append(f'# batch {batch}: types {sorted(set(t for t, *_ in placed))}, {len(placed)} placements')
            last_origin = {}
            for t, job, d, o in placed:
                if t not in rides:
                    rides[t] = len(rides)
                    s.cmd(f'cmd 6 ebx=1 edx={t:#x}                    # CREATE_RIDE type {t} -> ride {rides[t]}')
            s.tick += 1
            for t, job, d, o in placed:
                r = rides[t]
                if job[0] == 'maze':
                    tx, ty = o
                    for i in range(4):
                        for j in range(4):
                            walls = (0x1111 * (1 + (i + 2 * j) % 15)) & 0xFFFF
                            s.cmd(f'cmd 48 eax={(tx + i) * 32:#x} ebx={(walls & 0xFF) << 8 | 1:#x} '
                                  f'ecx={(ty + j) * 32:#x} edx={(walls >> 8) << 8 | r:#x} edi={GROUND_Z:#x}')
                    continue
                p, z = job
                if o == 'stack':                       # same tile and direction as the base
                    if t not in last_origin:
                        continue
                    o, d = last_origin[t]
                last_origin.setdefault(t, (o, d))
                tx, ty = o
                s.cmd(f'cmd 3 eax={tx * 32:#x} ebx={d << 8 | 1:#x} ecx={ty * 32:#x} edx={p << 8 | r:#x} edi={z:#x}')
                total += 1
            s.tick += 1
            s.frame = s.tick + 2
            view(s)
            s.sync()
            for r in sorted(rides.values()):
                s.cmd(f'cmd 7 ebx=1 edx={r:#x}                       # DEMOLISH_RIDE {r}')
            s.tick += 2
            s.frame = s.tick
            jobs = [(t, job) for t, job, d, o in rest]
            batch += 1
    s.sync()
    L.append(f'tick {s.tick + 5} quit')
    return L, total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='what', required=True)
    p1 = sub.add_parser('probe-script'); p1.add_argument('out')
    p2 = sub.add_parser('probe-parse'); p2.add_argument('trace'); p2.add_argument('out', nargs='?', default=DEFAULT_MAP)
    p3 = sub.add_parser('case'); p3.add_argument('types'); p3.add_argument('--map', default=DEFAULT_MAP)
    p3.add_argument('--seed', type=int, default=7300000)
    p3.add_argument('--random-dirs', action='store_true')
    p4 = sub.add_parser('pieces'); p4.add_argument('--map', default=DEFAULT_MAP)
    a = ap.parse_args()
    if a.what == 'probe-script':
        probe_script(a.out)
    elif a.what == 'probe-parse':
        probe_parse(a.trace, a.out)
    elif a.what == 'pieces':
        exe, smap = Exe(), json.load(open(a.map))
        for t in range(49):
            ps = allowed_pieces(exe, t, smap)
            print(t, len(ps), ' '.join(f'{p:02x}' for p in ps))
    else:
        exe, smap = Exe(), json.load(open(a.map))
        types = [int(x, 0) for x in a.types.split(',')]
        import random
        L, total = case(types, smap, exe, a.seed, random.Random(a.seed) if a.random_dirs else None)
        print('\n'.join(L))
        print(f'# {total} pieces')


if __name__ == '__main__':
    main()
