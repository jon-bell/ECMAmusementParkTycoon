#!/usr/bin/env python3
"""Build a small working park in Forest Frontiers with game commands, then let it run.

Every action is a game command (conventions: corpus/COMMANDS.md), applied at fixed ticks:
  loan, footpaths, flat rides and stalls (only types Forest Frontiers has invented), a car-ride
  circuit, ride entrances and exits, opening the rides and the park, prices, entrance fee, staff
  (hired onto the paths, with orders, patrol areas and uniform colours), research funding and
  priorities, a marketing campaign, scenery, a fence, land and water edits, land purchase.
Then the park runs for the requested number of ticks (guests arrive, ride, eat, litter; staff
work; rides break down; month-end finances; research progresses). Optional mid-run actions
(price changes, closing and reopening a ride, firing staff, demolishing a ride) exercise the
same commands on a populated park.

Layout (tiles; open, owned, flat grass at height byte 24 east of the park entrance at (51,19);
the existing path ends at (51,30)):
  main street x=51, y=31..57; cross street y=44, x=44..60
  3x3 flat rides west of the main street (centre x=48), entrances/exits at x=50 facing west
  stalls on the main street's east side (x=52) facing it
  a car-ride circuit (5x4) south-east, station on its north side, entrance/exit to the cross street

  park.py [--ticks N] [--variant public|heldout]
"""
import argparse

D = {0: (-1, 0), 1: (0, 1), 2: (1, 0), 3: (0, -1)}
Z = 0x60            # ground z (height byte 24 * 4)
H = 0x18            # ground height byte (footpath dl)
OBJECTIVE_CLOSE = (427, 156)
# sprite indices of the five staff hired at tick 13 (handyman, handyman, mechanic, security,
# entertainer), read from TR_REGS_OUT2 of a run of the variant; None = not measured yet
STAFF_SPRITES = {'public': [0x45, 0x46, 0x2E, 0x76, 0x68], 'heldout': [0x45, 0x46, 0x2E, 0x76, 0x68]}


class S:
    def __init__(self):
        self.L = []

    def at(self, tick, line, note=''):
        self.L.append(f'tick {tick} {line}' + (f'   # {note}' if note else ''))


def path(s, t, x, y, kind=1):
    s.at(t, f'cmd 17 eax={x * 32:#x} ebx=1 ecx={y * 32:#x} edx={kind << 8 | H:#x} edi=0')


def track(s, t, ride, x, y, d, piece, z=Z, note=''):
    s.at(t, f'cmd 3 eax={x * 32:#x} ebx={d << 8 | 1:#x} ecx={y * 32:#x} edx={piece << 8 | ride:#x} edi={z:#x}', note)


def entrance(s, t, ride, x, y, toward, exit_=False, station=0):
    s.at(t, f'cmd 12 eax={x * 32:#x} ebx={toward << 8 | 1:#x} ecx={y * 32:#x} edx={int(exit_) << 8 | ride:#x} '
            f'edi={station}', 'exit' if exit_ else 'entrance')


def car_loop(s, t, ride, x0, y0, w, h, turn=0x33):
    """Rectangle circuit heading -x from (x0,y0), turning with `turn` (+1 direction per corner);
    the first three straight pieces are station pieces. Returns the station tiles."""
    pos, d, st = (x0, y0), 0, []
    for side, n in enumerate((w, h, w, h)):
        for i in range(n - 1):
            p = 1 if side == 0 and i < 3 else 0
            if p:
                st.append(pos)
            track(s, t, ride, pos[0], pos[1], d, p)
            pos = (pos[0] + D[d][0], pos[1] + D[d][1])
        track(s, t, ride, pos[0], pos[1], d, turn)
        d = (d + 1) % 4
        pos = (pos[0] + D[d][0], pos[1] + D[d][1])
    return st


def build(variant='public', ticks=33000, seed=None):
    s = S()
    seed = seed or (7400000 if variant == 'public' else 7400777)
    s.L += [f'seed {seed}', 'frame 1 load 0',
            f'frame +10 mouse {OBJECTIVE_CLOSE[0]} {OBJECTIVE_CLOSE[1]} 1',
            f'frame +12 mouse {OBJECTIVE_CLOSE[0]} {OBJECTIVE_CLOSE[1]} 3']
    t = 2
    s.at(t, 'cmd 44 ebx=1 edx=0x493e0', 'SET_LOAN to the maximum (30,000.0)')
    s.at(t, 'cmd 45 ebx=1 edx=3', 'RESEARCH funding level 3')
    s.at(t, 'cmd 45 ebx=0x101 edx=0x3f', 'RESEARCH priorities: all categories')
    t = 3
    for y in range(31, 58):
        path(s, t, 51, y)
    for x in list(range(45, 51)) + list(range(52, 61)):
        path(s, t, x, 44)
    t = 4
    # flat rides west of the main street: (type, centre y); 3x3 piece 0x7B
    flats = [(33, 33), (46, 37), (47, 41)] if variant == 'public' else [(47, 33), (33, 37), (46, 41)]
    ride = 0
    rides = []
    for typ, cy in flats:
        s.at(t, f'cmd 6 ebx=1 edx={typ:#x}', f'CREATE_RIDE type {typ} -> ride {ride}')
        track(s, t + 1, ride, 48, cy, 0, 0x7B)
        entrance(s, t + 2, ride, 50, cy, 0)
        entrance(s, t + 2, ride, 50, cy + 1, 0, exit_=True)
        rides.append(ride)
        ride += 1
    # stalls east of the main street, facing it (direction 0 = toward -x)
    stalls = [(28, 33), (32, 35), (30, 37), (36, 39)] if variant == 'public' else [(30, 33), (36, 35), (32, 37), (28, 39)]
    for typ, y in stalls:
        s.at(t, f'cmd 6 ebx=1 edx={typ:#x}', f'CREATE_RIDE type {typ} -> ride {ride}')
        track(s, t + 1, ride, 52, y, 0, 0x76)
        rides.append(ride)
        ride += 1
    t = 8
    # car ride (type 11) circuit; entrance/exit north of the station, onto the cross street
    s.at(t, 'cmd 6 ebx=1 edx=0xb', f'CREATE_RIDE car ride -> ride {ride}')
    st = car_loop(s, t + 1, ride, 58, 46, 5, 4)
    entrance(s, t + 2, ride, st[0][0], st[0][1] - 1, 1)
    entrance(s, t + 2, ride, st[1][0], st[1][1] - 1, 1, exit_=True)
    rides.append(ride)
    car = ride
    ride += 1
    s.at(11, f'cmd 9 ebx=0x0001 edx={0x200 | car:#x}', 'SET_RIDE_VEHICLES car ride: 2 trains (ride still closed)')
    t = 12
    for r in rides:
        s.at(t, f'cmd 8 ebx=1 edx={0x100 | r:#x}', f'SET_RIDE_STATUS ride {r} open')
    s.at(t, 'cmd 33 ebx=1 edx=0x100', 'SET_PARK_OPEN')
    s.at(t, 'cmd 38 ebx=1 edi=50', 'SET_PARK_ENTRANCE_FEE 5.0')
    for r in rides[:3]:
        s.at(t, f'cmd 20 ebx=1 edx={r:#x} edi=15', f'SET_RIDE_PRICE ride {r} 1.5')
    s.at(t, f'cmd 20 ebx=1 edx={car:#x} edi=20', 'SET_RIDE_PRICE car ride 2.0')
    t = 13
    # staff hired onto the main street (bh = type; ax,cx,dx = x,y,z of a path tile)
    for k, (typ, y) in enumerate([(0, 32), (0, 50), (1, 40), (2, 45), (3, 36)]):
        s.at(t, f'cmd 28 eax={51 * 32 + 16:#x} ebx={typ << 8 | 1:#x} ecx={y * 32 + 16:#x} edx={Z + 0:#x}',
             f'HIRE_NEW_STAFF type {typ} at (51,{y})')
    s.at(t, 'cmd 39 ebx=0x0001 edx=0x0700', 'SET_STAFF_COLOUR handymen colour 7')
    t = 15
    # scenery: small scenery items beside the paths, a fence, land and water edits, land purchase
    for k, x in enumerate(range(53, 60, 2)):
        s.at(t, f'cmd 15 eax={x * 32:#x} ebx={(k % 4) << 8 | 1:#x} ecx={43 * 32:#x} edx=0', 'PLACE_SCENERY')
    s.at(t, f'cmd 40 eax={60 * 32:#x} ebx=1 ecx={45 * 32:#x} edx=0', 'PLACE_FENCE')
    s.at(t, 'cmd 47 ebx=0x0401 edx=0x0004', 'START_MARKETING park advert, 4 weeks')
    t = 16
    # landscaping in the south-east corner of the open area (no rides there)
    s.at(t, f'cmd 19 eax={56 * 32:#x} ebx=1 ecx={52 * 32:#x} edx=0xff01 edi={58 * 32:#x} ebp={54 * 32:#x}',
         'CHANGE_SURFACE_STYLE 3x3 to style 1')
    s.at(t, f'cmd 22 eax={60 * 32:#x} ebx=1 ecx={56 * 32:#x} edx={60 * 32 | (61 * 32) << 16:#x} '
            f'ebp={56 * 32 | (57 * 32) << 16:#x} edi=4', 'RAISE_LAND 2x2')
    s.at(t, f'cmd 23 eax={56 * 32:#x} ebx=1 ecx={57 * 32:#x} edx={55 * 32 | (57 * 32) << 16:#x} '
            f'ebp={56 * 32 | (57 * 32) << 16:#x} edi=4', 'LOWER_LAND 3x2')
    s.at(t + 1, f'cmd 23 eax={56 * 32:#x} ebx=1 ecx={57 * 32:#x} edx={55 * 32 | (57 * 32) << 16:#x} '
                f'ebp={56 * 32 | (57 * 32) << 16:#x} edi=4', 'LOWER_LAND again')
    s.at(t + 2, f'cmd 25 eax={55 * 32:#x} ebx=1 ecx={56 * 32:#x} edi={57 * 32:#x} ebp={57 * 32:#x}', 'RAISE_WATER (pond)')
    s.at(t + 2, f'cmd 24 eax={64 * 32:#x} ebx=1 ecx={52 * 32:#x} edx={64 * 32 | (64 * 32) << 16:#x} '
                f'ebp={52 * 32 | (52 * 32) << 16:#x} edi=1', 'EDIT_LAND_SMOOTH raise')
    s.at(t + 2, f'cmd 34 eax={60 * 32:#x} ebx=1 ecx={25 * 32:#x} edx=0', 'BUY_LAND_RIGHTS (60,25)')
    t = 20
    # ride settings on the car ride and the first flat ride
    s.at(t, f'cmd 11 ebx=0x0501 edx={0x200 | car:#x}', 'SET_RIDE_SETTING car ride min wait 5')
    s.at(t, f'cmd 11 ebx=0x0101 edx={0x500 | car:#x}', 'SET_RIDE_SETTING car ride inspection interval 1')
    s.at(t, f'cmd 0 ebx=0x0001 edx={0x500 | rides[0]:#x} edi=0', 'SET_RIDE_APPEARANCE track colour 5')
    s.at(t, f'cmd 10 eax=1 ebx=1 edx=0x4b524150 ebp=0x44524f43 edi=0', 'SET_RIDE_NAME chunk 0 "PARKCORD"')
    s.at(t, 'cmd 10 eax=2 ebx=1 edx=0 ebp=0 edi=0', 'SET_RIDE_NAME chunk 1')
    s.at(t, f'cmd 10 eax=0 ebx={rides[0] << 8 | 1:#x} edx=0 ebp=0 edi=0', 'SET_RIDE_NAME commit')
    # staff by sprite index (the hire command returns it in edi; the values below were read from a
    # run of this script: they depend only on the script up to tick 13, which these commands follow)
    sp = STAFF_SPRITES[variant]
    if sp:
        t = 21
        s.at(t, f'cmd 31 ebx=0x0701 edx={sp[0]:#x}', 'SET_STAFF_ORDERS handyman 1: sweep, water, bins')
        s.at(t, f'cmd 29 eax={51 * 32:#x} ebx=1 ecx={36 * 32:#x} edx={sp[1]:#x}', 'SET_STAFF_PATROL handyman 2')
        s.at(t, f'cmd 29 eax={51 * 32:#x} ebx=1 ecx={52 * 32:#x} edx={sp[1]:#x}', 'SET_STAFF_PATROL handyman 2')
        s.at(t, f'cmd 31 ebx=0x8201 edx={sp[4]:#x}', 'SET_STAFF_COSTUME entertainer costume 2')
        s.at(t, f'cmd 21 eax=1 ebx=1 ecx={sp[0]:#x} edx=0x45544550 ebp=0 edi=0', 'SET_PEEP_NAME chunk 0 "PETE"')
        s.at(t, 'cmd 21 eax=2 ebx=1 edx=0 ebp=0 edi=0', 'SET_PEEP_NAME chunk 1')
        s.at(t, 'cmd 21 eax=0 ebx=1 edx=0 ebp=0 edi=0', 'SET_PEEP_NAME commit')
    s.at(22, 'cmd 32 eax=1 ebx=1 edx=0x45524f43 ebp=0x4b524150 edi=0', 'SET_PARK_NAME chunk 0 "COREPARK"')
    s.at(22, 'cmd 32 eax=2 ebx=1 edx=0 ebp=0 edi=0', 'SET_PARK_NAME chunk 1')
    s.at(22, 'cmd 32 eax=0 ebx=1 edx=0 ebp=0 edi=0', 'SET_PARK_NAME commit')
    s.at(22, f'cmd 42 eax={63 * 32:#x} ebx=0x0101 ecx={33 * 32:#x} edx=0x0302 edi=0', 'PLACE_LARGE_SCENERY type 0')
    # mid-run actions on the populated park
    m = ticks // 3
    s.at(m, f'cmd 20 ebx=1 edx={rides[1]:#x} edi=25', 'SET_RIDE_PRICE raised')
    s.at(m, f'cmd 8 ebx=1 edx={rides[2]:#x}', 'SET_RIDE_STATUS close')
    s.at(m + 200, f'cmd 8 ebx=1 edx={0x200 | rides[2]:#x}', 'SET_RIDE_STATUS testing')
    s.at(m + 400, f'cmd 8 ebx=1 edx={0x100 | rides[2]:#x}', 'SET_RIDE_STATUS open')
    s.at(m + 500, 'cmd 44 ebx=1 edx=0x3a980', 'SET_LOAN repay part (24,000.0)')
    s.at(2 * m, 'cmd 38 ebx=1 edi=30', 'SET_PARK_ENTRANCE_FEE lowered')
    s.at(2 * m, f'cmd 8 ebx=1 edx={rides[-2]:#x}', 'SET_RIDE_STATUS close a stall')
    s.at(2 * m + 10, f'cmd 7 ebx=1 edx={rides[-2]:#x}', 'DEMOLISH_RIDE the stall')
    s.at(2 * m + 20, f'cmd 26 eax={55 * 32:#x} ebx=1 ecx={56 * 32:#x} edi={57 * 32:#x} ebp={57 * 32:#x}', 'LOWER_WATER')
    s.at(2 * m + 20, f'cmd 41 eax={60 * 32:#x} ebx=1 ecx={45 * 32:#x} edx=0', 'REMOVE_FENCE')
    s.at(2 * m + 20, f'cmd 43 eax={63 * 32:#x} ebx=1 ecx={33 * 32:#x} edx={H:#x}', 'REMOVE_LARGE_SCENERY')
    s.at(2 * m + 20, f'cmd 18 eax={51 * 32:#x} ebx=1 ecx={57 * 32:#x} edx={H:#x}', 'REMOVE_FOOTPATH end of the main street')
    if sp:
        s.at(2 * m + 30, f'cmd 30 ebx=1 edx={sp[3]:#x}', 'FIRE_STAFF security guard')
    s.at(2 * m + 40, f'cmd 28 eax={51 * 32 + 16:#x} ebx=0x0101 ecx={48 * 32 + 16:#x} edx={Z:#x}', 'HIRE_NEW_STAFF mechanic')
    s.L.append(f'tick {ticks} quit')
    return s.L


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ticks', type=int, default=33000)
    ap.add_argument('--variant', default='public')
    a = ap.parse_args()
    print('\n'.join(build(a.variant, a.ticks)))
