#!/usr/bin/env python3
"""HOST debugging diff of two API traces (the oracle's and the lift host's, RCTHOOK_SPIKE=apitrace).

  python3 lift/test/host/tools/atdiff.py ORACLE/apitrace.txt LIFT/apitrace.txt
          [--ignore NAME,..] [--noise NAME[:N],..] [--skip K]

Canonical forms of tools/apitrace.py, then tolerances specific to comparing a JS host with Wine
(a debugging instrument, not a gate; every tolerance is listed here):
  1. stack pointers compare as 'sp' whatever their offset (Wine's own frames have other sizes);
  2. pointers into memory no canonical region names (Wine or hook-DLL statics) compare as '?ptr';
  3. heap pointers compare by region only (offsets shift with C-runtime allocation history);
  4. --noise NAME[:N]: NAME's C records lose their struct bytes and its R records keep only the
     first N struct bytes (stale stack bytes Wine leaves in caller buffers);
  5. --ignore NAME: as tools/apitrace.py diff.
"""
import re, sys, argparse
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "tools"))
import apitrace as AT

ap = argparse.ArgumentParser()
ap.add_argument('a'); ap.add_argument('b')
ap.add_argument('--ignore', default=''); ap.add_argument('--noise', default=''); ap.add_argument('--context', type=int, default=8)
ap.add_argument('--skip', type=int, default=0, help='report the N+1-th divergence (resync by line)')
a = ap.parse_args()
ign = set(x for x in a.ignore.split(',') if x)
noise = {}
for s in a.noise.split(','):
    if s:
        n, _, k = s.partition(':'); noise[n] = int(k) if k else 0

def norm(r, line):
    line = re.sub(r'sp[+-][0-9a-f]+', 'sp', line)
    line = re.sub(r'\bstk\b', 'sp', line)
    line = re.sub(r'\?[0-9a-f]{5,8}\b', '?ptr', line)   # pointers into memory no region names (OS or hook DLL statics)
    line = re.sub(r'\b([AD]\d+)\+[0-9a-f]+', r'\1+?', line)   # heap offsets shift with the per-run environment size
    nm = getattr(r, 'name', None)
    if nm in noise:
        if r.t == 'C':
            line = re.sub(r'=\{[^}]*\}', '={}', line)
        elif r.t == 'R':
            k = noise[nm]
            def cut(m):
                h = m.group(1).replace(',', '')
                return '={' + h[:2 * k] + '}'
            line = re.sub(r'=\{([^}]*)\}', cut, line)
    if r.t in ('B',):   # callback esp is not comparable
        p = line.split(' '); 
        if len(p) > 6: p[6] = '*'; line = ' '.join(p)
    return line

sigs = AT.Sigs()
A = [(r, norm(r, l)) for r, l in AT.canon_stream(a.a, sigs, False, ign)]
B = [(r, norm(r, l)) for r, l in AT.canon_stream(a.b, sigs, False, ign)]
n = min(len(A), len(B))
skipped = 0
for i in range(n):
    if A[i][1] != B[i][1]:
        if skipped < a.skip:
            skipped += 1; continue
        print(f'FIRST DIVERGENCE at record {i} of {len(A)} / {len(B)}')
        for j in range(max(0, i - a.context), i): print('   ', A[j][1][:260])
        print('  A:', A[i][1][:600]); print('  B:', B[i][1][:600])
        print('  A raw:', A[i][0].line[:400]); print('  B raw:', B[i][0].line[:400])
        sys.exit(1)
print(f'IDENTICAL over {n} records (A {len(A)}, B {len(B)})')
sys.exit(0 if len(A) == len(B) else 1)
