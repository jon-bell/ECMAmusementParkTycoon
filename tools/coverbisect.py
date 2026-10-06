#!/usr/bin/env python3
"""Find addresses in a breakpoint list that must not hold an int3: code-section bytes the game
reads as data (tables the static CFG mistook for code). A subset of the list is armed in one
oracle run (RCTHOOK_SPIKE=cover=...); the subset is bad if the run fails or its RNG trace differs
from a reference run of the same script. Bad subsets are split recursively, in parallel.

  coverbisect.py <addrs.bin> <script> <reference trace.bin> <outdir> [--ways 48] [--jobs 48]
Writes <outdir>/bad.bin (uint32 addresses) and prints the bad addresses.
"""
import argparse
import os
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import rcttrace as T  # noqa: E402


def winpath(p):
    return 'Z:' + os.path.abspath(p).replace('/', '\\')


def trial(addrs, script, ref, d):
    os.makedirs(d, exist_ok=True)
    lst = os.path.join(d, 'addrs.bin')
    with open(lst, 'wb') as f:
        f.write(struct.pack(f'<{len(addrs)}I', *addrs))
    env = dict(os.environ, ORACLE_TIMEOUT='300')
    p = subprocess.run([os.path.join(ROOT, 'scripts', 'oracle-run.sh'), os.path.join(d, 'run'), script, '--',
                        f'RCTHOOK_SPIKE=cover={winpath(lst)}'], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        return False
    same, _ = T.compare(ref, os.path.join(d, 'run', 'trace.bin'), 'rng')
    return same


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('addrs'); ap.add_argument('script'); ap.add_argument('ref'); ap.add_argument('out')
    ap.add_argument('--ways', type=int, default=48); ap.add_argument('--jobs', type=int, default=48)
    a = ap.parse_args()
    data = open(a.addrs, 'rb').read()
    addrs = sorted(struct.unpack(f'<{len(data) // 4}I', data))
    ref = T.load(a.ref)
    bad, frontier, level = [], [addrs], 0
    with ThreadPoolExecutor(a.jobs) as ex:
        while frontier:
            groups = []
            for g in frontier:
                if len(g) == 1:
                    groups.append(g)
                    continue
                k = min(a.ways, len(g))
                step = (len(g) + k - 1) // k
                groups += [g[i:i + step] for i in range(0, len(g), step)]
            dirs = [os.path.join(a.out, f'l{level}', f'g{i}') for i in range(len(groups))]
            oks = list(ex.map(lambda gd: trial(gd[0], a.script, ref, gd[1]), zip(groups, dirs)))
            failing = [g for g, ok in zip(groups, oks) if not ok]
            print(f'level {level}: {len(groups)} groups, {len(failing)} failing '
                  f'({sum(len(g) for g in failing)} addresses)', flush=True)
            bad += [g[0] for g in failing if len(g) == 1]
            frontier = [g for g in failing if len(g) > 1]
            level += 1
    bad.sort()
    with open(os.path.join(a.out, 'bad.bin'), 'wb') as f:
        f.write(struct.pack(f'<{len(bad)}I', *bad))
    print('bad:', ' '.join(hex(x) for x in bad))


if __name__ == '__main__':
    main()
