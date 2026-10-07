#!/usr/bin/env python3
"""Generate a 'tour' fragment: view the whole park from all four rotations.

The tour drives the game's own view controls only: the toolbar zoom and rotate buttons (mouse
clicks in game coordinates on the 640x480 game window) and the arrow keys (DirectInput scan
codes), which scroll the main view. Scrolling is clamped by the game to the map, so the raster
below is position-independent: it first scrolls into the top-left clamp, then sweeps rows.

  tour.py [--zoom-outs 2] [--rows 4] [--row-frames 450] [--step-frames 80] [--rotations 4]
Prints script lines with 'frame +N' times starting at --start (frames after the last load).
"""
import argparse

UP, LEFT, RIGHT, DOWN = 0xC8, 0xCB, 0xCD, 0xD0
ZOOM_OUT, ZOOM_IN, ROTATE = (117, 14), (146, 14), (180, 14)


def click(L, t, xy):
    L.append(f'frame +{t} mouse {xy[0]} {xy[1]} 1')
    L.append(f'frame +{t + 2} mouse {xy[0]} {xy[1]} 3')
    return t + 4


def hold(L, t, keys, n):
    for k in keys:
        L.append(f'frame +{t} key {k:#x} 1')
    for k in keys:
        L.append(f'frame +{t + n} key {k:#x} 0')
    return t + n + 1


def tour(start, zoom_outs=2, rows=4, row_frames=450, step_frames=80, rotations=4, corner_frames=600):
    """corner_frames > 0: start each rotation from the top-left clamp (whole-map raster).
    corner_frames = 0: local raster around the current view: up and left by half the raster,
    then the rows, then back to the start, so every rotation sweeps the same neighbourhood."""
    L = [f'# tour: {rotations} rotations x {rows} rows at zoom-out level {zoom_outs}']
    t = start
    for _ in range(zoom_outs):
        t = click(L, t, ZOOM_OUT)
    for r in range(rotations):
        if corner_frames:
            t = hold(L, t, (UP, LEFT), corner_frames)
        else:
            t = hold(L, t, (LEFT,), row_frames // 2)
            if rows > 1:
                t = hold(L, t, (UP,), step_frames * (rows - 1) // 2)
        for i in range(rows):
            t = hold(L, t, (RIGHT if i % 2 == 0 else LEFT,), row_frames)
            if i + 1 < rows:
                t = hold(L, t, (DOWN,), step_frames)
        if not corner_frames:   # back to the starting view
            if rows % 2:
                t = hold(L, t, (LEFT,), row_frames // 2)
            else:
                t = hold(L, t, (RIGHT,), row_frames // 2)
            if rows > 1:
                t = hold(L, t, (UP,), step_frames * (rows - 1) - step_frames * (rows - 1) // 2)
        if r + 1 < rotations:
            t = click(L, t, ROTATE)
    t = click(L, t, ROTATE)          # back to the original rotation
    for _ in range(zoom_outs):
        t = click(L, t, ZOOM_IN)
    return L, t


VIEW_MENU = (210, 14)
VIEW_ITEMS = {'underground': 41, 'underwater': 50, 'see-through rides': 70, 'see-through scenery': 80,
              'invisible supports': 90, 'invisible people': 100, 'gridlines': 120, 'height marks land': 130,
              'height marks track': 140, 'height marks paths': 150}
VIEW_GROUPS = (['underground'],
               ['underground', 'see-through rides', 'see-through scenery', 'invisible supports', 'invisible people'],
               ['see-through rides', 'see-through scenery', 'invisible supports', 'invisible people', 'gridlines',
                'height marks land', 'height marks track', 'height marks paths'])


def viewopts(start):
    """Toggle the View menu's options in three groups (each item toggles), with a local 1:2 tour
    after each group: the underground view, see-through and invisible modes and height marks are
    separate painter paths."""
    L, t = [], start
    for group in VIEW_GROUPS:
        for item in group:
            L += [f'frame +{t} mouse {VIEW_MENU[0]} {VIEW_MENU[1]} 1', f'frame +{t + 2} mouse {VIEW_MENU[0]} {VIEW_MENU[1]} 3',
                  f'frame +{t + 6} mouse 255 {VIEW_ITEMS[item]} 1', f'frame +{t + 8} mouse 255 {VIEW_ITEMS[item]} 3']
            t += 12
        T, t = tour(t, zoom_outs=1, rows=3, row_frames=300, step_frames=60, corner_frames=0)
        L += [x for x in T if not x.startswith('#')]
        t += 5
    return L, t


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--start', type=int, default=30)
    ap.add_argument('--zoom-outs', type=int, default=2)
    ap.add_argument('--rows', type=int, default=4)
    ap.add_argument('--row-frames', type=int, default=450)
    ap.add_argument('--step-frames', type=int, default=80)
    ap.add_argument('--rotations', type=int, default=4)
    ap.add_argument('--corner-frames', type=int, default=600)
    a = ap.parse_args()
    L, t = tour(a.start, a.zoom_outs, a.rows, a.row_frames, a.step_frames, a.rotations, a.corner_frames)
    print('\n'.join(L))
    print(f'# tour ends at frame +{t}')
