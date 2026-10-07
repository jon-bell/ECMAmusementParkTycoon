#!/usr/bin/env python3
"""Generate a 'UI tour' fragment: open the game's windows and click through their tabs.

Clicks go into the game's own mouse queue in game coordinates (640x480 window). Positions were
found from screenshots of the windows (`shot`) in the 640x480 layout; they hold for any park as
long as each session starts from a freshly loaded scenario, because window placement depends only
on which windows are open. Each session therefore starts with a scenario load (the same routine
the New Game window uses), so sessions do not depend on each other's window stacking.

Sessions (each: load, close the objective window, then the clicks):
  rides     ride list; for each listed ride: open its window, click its 8 tabs
  guests    guest list (2 tabs); open a few guests' windows, click their 6 tabs
  staff     staff list (4 tabs); open the first staff member's window, click its 3 tabs
  finances  finance window, 5 tabs
  research  research window, 2 tabs
  park      park window, 7 tabs
  misc      map, recent messages, scenery window tabs, land window, path window, new-rides tabs
"""

TOOLBAR = {'file': 40, 'view': 210, 'map': 238, 'land': 283, 'water': 313, 'scenery': 342, 'path': 372,
           'newride': 400, 'finances': 443, 'research': 470, 'rides': 501, 'park': 530, 'guests': 560,
           'staff': 590, 'messages': 622}
OBJECTIVE_CLOSE = (427, 156)
SIDE_CLOSE = (632, 39)   # close box of a ride/guest/staff window opened beside its list window


class Script:
    def __init__(self, t=10):
        self.L, self.t = [], t

    def click(self, x, y, wait=12, button=1):
        self.L.append(f'frame +{self.t} mouse {x} {y} {button}')
        self.L.append(f'frame +{self.t + 2} mouse {x} {y} {button + 2}')
        self.t += wait

    def toolbar(self, name, wait=15):
        self.click(TOOLBAR[name], 14, wait)

    def note(self, s):
        self.L.append(f'# {s}')


def session(scenario, body, rows=None):
    s = Script()
    s.L.append(f'frame +30 load {scenario}')   # relative to the previous load; resets all windows
    s.click(*OBJECTIVE_CLOSE)
    body(s, rows)
    return s.L


def rides(s, rows):
    s.note('rides: ride list, then every ride window and its tabs')
    s.toolbar('rides')
    for r in range(rows or 8):
        s.click(60, 100 + 10 * r, 15)
        for x in (404, 435, 465, 496, 527, 557, 588, 619):
            s.click(x, 61, 15)
        s.click(*SIDE_CLOSE)


def guests(s, rows):
    s.note('guests: list tabs, guest windows and their tabs')
    s.toolbar('guests')
    s.click(55, 65, 15)
    s.click(20, 65, 15)
    for r in range(rows or 3):
        s.click(40, 113 + 10 * r, 15)
        for x in (464, 495, 525, 556, 587, 617):
            s.click(x, 61, 15)
        s.click(*SIDE_CLOSE)


def staff(s, rows):
    s.note('staff: list tabs, staff window tabs')
    s.toolbar('staff')
    for x in (55, 90, 123, 20):
        s.click(x, 65, 15)
    s.click(40, 113, 15)
    for x in (471, 501, 532):
        s.click(x, 61, 15)


def finances(s, rows):
    s.note('finances: 5 tabs')
    s.toolbar('finances')
    for x in (57, 91, 126, 160, 23):
        s.click(x, 65, 20)


def research(s, rows):
    s.note('research: 2 tabs')
    s.toolbar('research')
    for x in (55, 20):
        s.click(x, 63, 20)


def park(s, rows):
    s.note('park: 7 tabs')
    s.toolbar('park')
    for x in (50, 80, 112, 145, 177, 205, 20):
        s.click(x, 63, 20)


def misc(s, rows):
    s.note('misc: map, messages, scenery tabs, land, path, new rides tabs')
    s.toolbar('map', 30)
    s.toolbar('messages', 20)
    s.toolbar('scenery', 15)
    for x in (52, 85, 126, 159, 194, 230, 21):
        s.click(x, 64, 15)
    s.toolbar('land', 15)
    s.toolbar('path', 15)
    s.toolbar('newride', 15)
    for x in (57, 90, 124, 158, 192, 24):
        s.click(x, 64, 15)


SESSIONS = {'rides': rides, 'guests': guests, 'staff': staff, 'finances': finances, 'research': research,
            'park': park, 'misc': misc}


def uitour(scenario, names=None, ride_rows=None):
    L = []
    for n in names or SESSIONS:
        L += session(scenario, SESSIONS[n], ride_rows if n == 'rides' else None)
    return L


if __name__ == '__main__':
    import sys
    print('\n'.join(uitour(int(sys.argv[1]) if len(sys.argv) > 1 else 3)))
