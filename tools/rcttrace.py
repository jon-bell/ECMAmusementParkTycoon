#!/usr/bin/env python3
"""Read and compare rcthook.dll traces (format: oracle/trace.h, 16-byte records).

  rcttrace.py summary  <trace.bin>          counts per record kind, ticks, RNG draws, final hash
  rcttrace.py finished <trace.bin>          exit 0 iff the run reached the script's quit
  rcttrace.py compare  <a.bin> <b.bin> [projection]
                                         first divergence (exit 0 iff identical); projections:
                                         core, game, input, os, game+input (default)
  rcttrace.py rng      <trace.bin> [n]      print the first n RNG draws
"""
import os
import re
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
_kinds = {}
with open(os.path.join(HERE, '..', 'oracle', 'trace.h')) as f:
    for m in re.finditer(r'(TR_\w+)\s*=\s*(0x[0-9A-Fa-f]+)', f.read()):
        _kinds[int(m.group(2), 16)] = m.group(1)
K = {v: k for k, v in _kinds.items()}

STATE_LO, STATE_HI, STATE2_LO, STATE2_HI, CHUNK = 0x5F4000, 0x9A161C, 0x9A2000, 0x9B2301, 0x10000


def chunk_range(i):
    n1 = (STATE_HI - STATE_LO + CHUNK - 1) // CHUNK
    if i < n1:
        lo = STATE_LO + i * CHUNK
        return lo, min(lo + CHUNK, STATE_HI)
    lo = STATE2_LO + (i - n1) * CHUNK
    return lo, min(lo + CHUNK, STATE2_HI)


def load(path):
    with open(path, 'rb') as f:
        data = f.read()
    n = len(data) // 16
    return list(struct.iter_unpack('<4I', data[:n * 16]))


# Projections (sets of record kinds compared between runs).
#   core  : the game's simulation behaviour as summarised by the RNG and the static state:
#           every RNG draw (tick, call site, value), RNG state at each tick start, a 64-bit hash of
#           DATASEG+DataSeg at each tick start (and per 64 KiB chunk), the final state hash.
#   game  : core + game commands (the game's own dispatcher entries with registers, results of
#           injected commands), scenario loads, run totals.
#   input : what the script fed in (keys, cursor, mouse events, pokes, injected command registers).
#   os    : what the OS fed in or the instrument observed (frames and the virtual clock, window
#           messages delivered/dropped, file opens, run configuration).
CORE = {K[k] for k in ('TR_RNG', 'TR_TICK', 'TR_STATE', 'TR_CHUNK', 'TR_FINAL')}
GAME = CORE | {K[k] for k in ('TR_COMMAND', 'TR_REGS_IN', 'TR_REGS_IN2', 'TR_REGS_OUT', 'TR_REGS_OUT2',
                              'TR_REGS_OUT3', 'TR_LOAD', 'TR_NOTE', 'TR_END')}
INPUT = {K[k] for k in ('TR_INPUT', 'TR_INJECT', 'TR_INJ_IN', 'TR_INJ_IN2')}
OS = {K[k] for k in ('TR_HEADER', 'TR_FRAME', 'TR_MSG', 'TR_MSG_DROP', 'TR_FILE')}
assert CORE | GAME | INPUT | OS == set(_kinds), set(_kinds) - (CORE | GAME | INPUT | OS)
PROJECTIONS = {'core': CORE, 'game': GAME, 'input': INPUT, 'os': OS, 'game+input': GAME | INPUT}


def projection(recs, kinds=None):
    kinds = PROJECTIONS['game+input'] if kinds is None else kinds
    return [r for r in recs if r[0] in kinds]


def fmt(r):
    k = _kinds.get(r[0], hex(r[0]))
    a, b, c = r[1:]
    if k == 'TR_RNG':
        return f'RNG tick={a} site={b:#08x} value={c:#010x}'
    if k == 'TR_TICK':
        return f'TICK {a} srand0={b:#010x} srand1={c:#010x}'
    if k in ('TR_STATE', 'TR_FINAL'):
        return f'{k[3:]} tick={a} hash={c:08x}{b:08x}'
    if k == 'TR_CHUNK':
        lo, hi = chunk_range(a)
        return f'CHUNK {a} [{lo:#x},{hi:#x}) hash={c:08x}{b:08x}'
    if k == 'TR_FRAME':
        return f'FRAME {a} vt={b} ticks={c}'
    if k == 'TR_COMMAND':
        return f'COMMAND tick={a} cmd={b & 0xff} flags={(b >> 8) & 0xff:#x} depth={b >> 16} site={c:#08x}'
    return f'{k} {a:#x} {b:#x} {c:#x}'


def summary(path):
    recs = load(path)
    cnt = Counter(_kinds.get(r[0], hex(r[0])) for r in recs)
    hdr = recs[0] if recs and recs[0][0] == K['TR_HEADER'] else None
    end = [r for r in recs if r[0] == K['TR_END']]
    fin = [r for r in recs if r[0] == K['TR_FINAL']]
    print(f'trace {path}: {len(recs)} records')
    if hdr:
        print(f'  version={hdr[1]} realtime={hdr[2]} quantum={hdr[3]}')
    for k, v in sorted(cnt.items()):
        print(f'  {k:12s} {v}')
    if end:
        print(f'  end: frames={end[-1][1]} ticks={end[-1][2]} rng_draws={end[-1][3]}')
    if fin:
        print(f'  final state hash {fin[-1][3]:08x}{fin[-1][2]:08x} at tick {fin[-1][1]}')
    sites = Counter(r[2] for r in recs if r[0] == K['TR_RNG'])
    print(f'  distinct RNG call sites: {len(sites)}')
    return recs


def finished(path):
    try:
        recs = load(path)
    except OSError:
        return False
    return any(r[0] == K['TR_FINAL'] for r in recs)


def compare(pa, pb, proj='game+input'):
    """Compare two traces under a named projection. Return (identical, report dict)."""
    ra_all, rb_all = (pa if isinstance(pa, list) else load(pa)), (pb if isinstance(pb, list) else load(pb))
    a, b = projection(ra_all, PROJECTIONS[proj]), projection(rb_all, PROJECTIONS[proj])
    rep = {'projection': proj, 'records_a': len(a), 'records_b': len(b),
           'rng_a': sum(r[0] == K['TR_RNG'] for r in a), 'rng_b': sum(r[0] == K['TR_RNG'] for r in b),
           'ticks_a': sum(r[0] == K['TR_TICK'] for r in a), 'ticks_b': sum(r[0] == K['TR_TICK'] for r in b),
           'states_a': sum(r[0] == K['TR_STATE'] for r in a)}
    n = min(len(a), len(b))
    i = next((i for i in range(n) if a[i] != b[i]), None)
    if i is None and len(a) == len(b):
        rep['identical'] = True
        return True, rep
    rep['identical'] = False
    if i is None:
        i = n
    rep['index'] = i
    tick = 0
    for r in a[:i]:
        if r[0] == K['TR_TICK']:
            tick = r[1]
    rep['tick'] = tick
    ra = a[i] if i < len(a) else None
    rb = b[i] if i < len(b) else None
    rep['a'] = fmt(ra) if ra else '<end of trace>'
    rep['b'] = fmt(rb) if rb else '<end of trace>'
    kind = ra[0] if ra else rb[0]
    rep['kind'] = _kinds.get(kind, hex(kind))
    # localise a state divergence: list differing chunks of the same state record
    if ra and rb and ra[0] == rb[0] == K['TR_CHUNK']:
        j, diff = i, []
        while j < n and a[j][0] == K['TR_CHUNK']:
            if a[j] != b[j]:
                lo, hi = chunk_range(a[j][1])
                diff.append(f'{lo:#x}-{hi:#x}')
            j += 1
        rep['chunks'] = diff
    ctx = [fmt(r) for r in a[max(0, i - 4):i]]
    rep['context'] = ctx
    return False, rep


def print_compare(ok, rep, out=sys.stdout):
    print(f"projection {rep['projection']}: records {rep['records_a']} vs {rep['records_b']}; "
          f"rng draws {rep['rng_a']} vs {rep['rng_b']}; ticks {rep['ticks_a']} vs {rep['ticks_b']}", file=out)
    if ok:
        print('IDENTICAL', file=out)
        return
    print(f"FIRST DIVERGENCE at record {rep['index']} (tick {rep['tick']}, kind {rep['kind']})", file=out)
    for c in rep['context']:
        print(f'    {c}', file=out)
    print(f"  A: {rep['a']}", file=out)
    print(f"  B: {rep['b']}", file=out)
    if rep.get('chunks'):
        print(f"  differing state chunks: {', '.join(rep['chunks'])}", file=out)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == 'summary':
        summary(argv[2])
        return 0
    if cmd == 'finished':
        return 0 if finished(argv[2]) else 1
    if cmd == 'compare':
        ok, rep = compare(argv[2], argv[3], argv[4] if len(argv) > 4 else 'game+input')
        print_compare(ok, rep)
        return 0 if ok else 1
    if cmd == 'rng':
        n = int(argv[3]) if len(argv) > 3 else 50
        for r in load(argv[2]):
            if r[0] == K['TR_RNG']:
                print(fmt(r))
                n -= 1
                if not n:
                    break
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
