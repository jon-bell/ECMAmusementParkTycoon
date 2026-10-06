#!/usr/bin/env python3
"""Find state locations that hold OS-allocated addresses: compare dumps taken at the same tick
from runs whose heap layout was shifted (RCTHOOK_SPIKE=heapshift=N). Differing dwords are
classified by the shift seen and clustered into regions.

  ptrmask.py <base_dump> <shifted_dump> [<shifted_dump> ...]   -> summary; --json writes the mask
"""
import json
import struct
import sys

STATE_LO, STATE_HI, STATE2_LO = 0x5F4000, 0x9A161C, 0x9A2000
N1 = STATE_HI - STATE_LO


def va(off):
    return STATE_LO + off if off < N1 else STATE2_LO + off - N1


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    base = open(args[0], 'rb').read()
    others = [open(p, 'rb').read() for p in args[1:]]
    diff = set()
    for o in others:
        for i in range(0, min(len(base), len(o)) - 3, 1):
            if base[i] != o[i]:
                diff.add(i & ~3)
    # dword view: aligned dwords containing a difference; classify unaligned too
    offs = sorted(diff)
    clusters = []
    for off in offs:
        if clusters and off - clusters[-1][1] <= 64:
            clusters[-1][1] = off
            clusters[-1][2] += 1
        else:
            clusters.append([off, off, 1])
    print(f'{len(offs)} dwords differ; {len(clusters)} regions')
    for s, e, n in sorted(clusters, key=lambda c: -c[2])[:40]:
        v = struct.unpack('<I', base[s:s + 4])[0]
        print(f'  {va(s):#x}-{va(e) + 4:#x}  {n:6d} dwords  stride~{(e - s) // max(1, n - 1) if n > 1 else 0:3d}  e.g. {v:#010x}')
    if '--json' in sys.argv:
        json.dump([va(o) for o in offs], open('ptrmask.json', 'w'))


if __name__ == '__main__':
    main()
