#!/usr/bin/env python3
"""Find every state value that depends on where the OS put memory, and check oracle/mask.h.

Two phases, each over pairs of oracle runs of the same script: <case>-base (clean) and
<case>-shift (adds heapshift=N, which moves the heap, VirtualAlloc regions, mappings, the screen
DIB and handle numbers).

  maskaudit.py candidates DIR... -o LIST.bin
        phase 1 (runs with RCTHOOK_SPIKE=ptrscan): every state address that pointed into mapped
        or private OS memory at any tick of any run -> LIST.bin (uint32 LE), the watch list
  maskaudit.py diff DIR...
        phase 2 (runs with RCTHOOK_SPIKE=watch=LIST.bin): a byte is layout-dependent iff its value
        differs between base and shift at some logged change (tools/watchdiff.c; the two logs must
        have the same (tick, address) sequence, which the comparison checks). Game data, including
        values that look like pointers by coincidence, is identical in both runs (the game is
        deterministic and the RNG traces agree). Reports each layout-dependent address, the cases
        showing it, and whether oracle/mask.h covers it; exit 1 if any is not covered.
"""
import glob
import os
import re
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
MASK_H = os.path.join(HERE, '..', 'oracle', 'mask.h')
SPRITE = (0x8DC0B4, 16, 38365)


def mask_bytes():
    covered = set()
    for ln in open(MASK_H):
        ln = ln.split('/*')[0]
        m = re.match(r'\s*MASK_DWORD\((0x[0-9A-Fa-f]+)\)', ln)
        if m:
            a = int(m.group(1), 16)
            covered.update(range(a, a + 4))
        m = re.match(r'\s*MASK_STRIDE\((0x[0-9A-Fa-f]+),\s*(\d+),\s*(\d+)\)', ln)
        if m:
            b, s, n = int(m.group(1), 16), int(m.group(2)), int(m.group(3))
            for i in range(n):
                covered.update(range(b + i * s, b + i * s + 4))
    return covered


def pairs(dirs, fname):
    for d in dirs:
        for base in sorted(glob.glob(os.path.join(d, '*-base', fname))):
            case = os.path.basename(os.path.dirname(base))[:-5]
            shift = os.path.join(d, case + '-shift', fname)
            if os.path.exists(shift):
                yield case, base, shift


def cmd_candidates(dirs, out):
    cand, nfiles = set(), 0
    for d in dirs:
        for f in glob.glob(os.path.join(d, '*', 'ptrscan.txt')):
            nfiles += 1
            for ln in open(f):
                if ln.startswith('#'):
                    continue
                p = ln.split()
                if p[1] in ('mapped', 'private'):
                    cand.add(int(p[0], 16))
    cand = sorted(cand)
    with open(out, 'wb') as f:
        f.write(struct.pack(f'<{len(cand)}I', *cand))
    print(f'{nfiles} ptrscan files, {len(cand)} candidate addresses -> {out}')


def load_watch(path):
    d = open(path, 'rb').read()
    v = struct.unpack(f'<{len(d) // 4}I', d)
    seq = defaultdict(list)
    for i in range(0, len(v) - 2, 3):
        seq[v[i + 1]].append((v[i], v[i + 2]))
    return seq


WATCHDIFF_SRC = os.path.join(HERE, 'watchdiff.c')
WATCHDIFF = os.path.join(HERE, '..', 'out', 'oi', 'bin', 'watchdiff')


def watchdiff(a, b):
    """{dword address: (xor mask, first tick, base value, shift value)} via tools/watchdiff.c"""
    import subprocess
    if not os.path.exists(WATCHDIFF) or os.path.getmtime(WATCHDIFF) < os.path.getmtime(WATCHDIFF_SRC):
        os.makedirs(os.path.dirname(WATCHDIFF), exist_ok=True)
        subprocess.run(['gcc', '-O2', '-o', WATCHDIFF, WATCHDIFF_SRC], check=True)
    p = subprocess.run([WATCHDIFF, a, b], stdout=subprocess.PIPE, text=True)
    if p.returncode == 2 or p.stdout.startswith('MISALIGNED'):
        raise SystemExit(f'{a} vs {b}: {p.stdout.strip()}')
    out = {}
    for ln in p.stdout.splitlines():
        ad, m, t, va, vb = ln.split()
        out[int(ad, 16)] = (int(m, 16), int(t), int(va, 16), int(vb, 16))
    return out


def cmd_diff(dirs):
    covered = mask_bytes()
    found = defaultdict(list)      # byte address -> [(case, first tick, base dword, shift dword)]
    npairs = 0
    for case, base, shift in pairs(dirs, 'watch.bin'):
        npairs += 1
        for addr, (m, t, va, vb) in watchdiff(base, shift).items():
            for k in range(4):
                if (m >> (8 * k)) & 0xFF:
                    found[addr + k].append((case, t, va, vb))
    ranges, cur = [], None
    for x in sorted(found):
        if cur and x == cur[1]:
            cur[1] += 1
        else:
            cur = [x, x + 1]
            ranges.append(cur)
    sprite = {SPRITE[0] + SPRITE[1] * i + k for i in range(SPRITE[2]) for k in range(4)}
    unc = sorted(x for x in found if x not in covered)
    nsprite = sum(1 for lo, hi in ranges if lo in sprite)
    print(f'{npairs} base/shift pairs; {len(found)} layout-dependent bytes in {len(ranges)} ranges '
          f'({nsprite} in the sprite table); {len(unc)} bytes not covered by oracle/mask.h')
    for lo, hi in ranges:
        if lo in sprite and all(x in covered for x in range(lo, hi)):
            continue
        cases = sorted({c for x in range(lo, hi) for c, _, _, _ in found[x]})
        cov = 'masked' if all(x in covered for x in range(lo, hi)) else \
            ('NOT MASKED' if not any(x in covered for x in range(lo, hi)) else 'PARTLY')
        c, t, va, vb = found[lo][0]
        print(f'  {lo:08x}..{hi:08x} {cov:10s} {len(cases):3d} case(s), e.g. {c} tick {t}: {va:08x} vs {vb:08x}')
    return 1 if unc else 0


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    if argv[1] == 'candidates':
        if '-o' not in argv:
            print(__doc__)
            return 2
        i = argv.index('-o')
        cmd_candidates(argv[2:i], argv[i + 1])
        return 0
    if argv[1] == 'diff':
        return cmd_diff(argv[2:])
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
