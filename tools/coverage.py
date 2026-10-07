#!/usr/bin/env python3
"""Instruction-weighted code coverage of oracle runs (RCTHOOK_SPIKE=cover=<blocks-all.bin>).

Each run directory holds cover_hits.bin (uint32 LE block starts that executed; the spike arms a
one-shot int3 at every block start of the static map). Blocks of the map end after every jump,
call and return, so a hit block start means every instruction of the block executed. An
instruction is attributed to the block whose start is the nearest block start at or before it.

  coverage.py [--map out/spikes/s1/cfg.json] [--json OUT] [--top N] RUN [RUN ...]

A RUN is a run directory, or NAME=DIR to label it. Runs whose label (or path) contains
'heldout' are counted as held-out, all others as public. Reported:
  - per section (.text, CODESEG, CodeSeg): blocks and instructions executed, union of all runs;
  - per run: CODESEG instructions, and instructions no other run reaches (unique);
  - public union vs held-out union, and what each reaches that the other does not;
  - functions entered (call targets of the map whose entry block executed);
  - game commands: handler entries hit (cfg game_commands), and, from trace.bin, the commands
    the game dispatched (id, apply flag, success) per run;
  - optionally the N largest functions by unexecuted CODESEG instructions (where to aim next).
Self-check: a run with an empty hit list, or hits outside the map, is reported as an error.
"""
import argparse
import bisect
import json
import os
import struct
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import rcttrace as T  # noqa: E402

SECTIONS = {'.text': (0x401000, 0x401000 + 0x1A1A6),
            'CODESEG': (0x41C000, 0x41C000 + 0x1CAC5D),
            'CodeSeg': (0x9B3000, 0x9B3000 + 0x9562)}


def section_of(a):
    for n, (lo, hi) in SECTIONS.items():
        if lo <= a < hi:
            return n
    return None


class Map:
    def __init__(self, path):
        d = json.load(open(path))
        self.blocks = sorted(d['blocks'])
        self.block_set = set(self.blocks)
        ins = sorted(d['instruction_starts'])
        # instructions per block: instruction starts in [block, next block)
        self.weight = {}
        j = 0
        for i, b in enumerate(self.blocks):
            nb = self.blocks[i + 1] if i + 1 < len(self.blocks) else 1 << 32
            j = bisect.bisect_left(ins, b, j)
            k = bisect.bisect_left(ins, nb, j)
            self.weight[b] = k - j
            j = k
        self.functions = sorted(d['functions'])
        self.commands = d['game_commands']
        self.total = Counter()
        self.total_blocks = Counter()
        for b in self.blocks:
            s = section_of(b)
            self.total[s] += self.weight[b]
            self.total_blocks[s] += 1
        # function extent (approximate): blocks from its entry to the next function entry
        self.func_of = {}
        fi = 0
        for b in self.blocks:
            while fi + 1 < len(self.functions) and self.functions[fi + 1] <= b:
                fi += 1
            if self.functions and self.functions[fi] <= b:
                self.func_of[b] = self.functions[fi]


def load_hits(run):
    p = os.path.join(run, 'cover_hits.bin')
    data = open(p, 'rb').read()
    return set(struct.unpack(f'<{len(data) // 4}I', data))


def commands_in_trace(run):
    """(cmd id, apply, ok) of every game_do_command entry. Success is known only for injected
    commands (TR_REGS_OUT ebx); for the game's own calls it is None."""
    p = os.path.join(run, 'trace.bin')
    if not os.path.exists(p):
        return []
    recs = T.load(p)
    out = []
    kc, kin, kout = T.K['TR_COMMAND'], T.K['TR_INJECT'], T.K['TR_REGS_OUT']
    pending = None
    for r in recs:
        if r[0] == kin:
            pending = len(out)
        elif r[0] == kc:
            depth = r[2] >> 16
            out.append([r[2] & 0xff, (r[2] >> 8) & 1, None, depth, r[3]])
        elif r[0] == kout and pending is not None:
            # the injected command's own TR_COMMAND record is the first one after TR_INJECT
            if pending < len(out):
                out[pending][2] = r[2] != 0x80000000
            pending = None
    return out


def instr(m, hits, sect=None):
    return sum(m.weight[b] for b in hits if sect is None or section_of(b) == sect)


def pct(a, b):
    return f'{100.0 * a / b:5.1f}%' if b else '  n/a'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('--map', default=os.path.join(ROOT, 'out', 'spikes', 's1', 'cfg.json'))
    ap.add_argument('--json')
    ap.add_argument('--top', type=int, default=0, help='list the N largest unexecuted functions')
    ap.add_argument('--quiet-runs', action='store_true', help='omit the per-run table')
    a = ap.parse_args()
    m = Map(a.map)

    runs = []
    errors = []
    for spec in a.runs:
        name, _, d = spec.rpartition('=')
        name = name or os.path.basename(os.path.normpath(d))
        if not os.path.exists(os.path.join(d, 'cover_hits.bin')):
            errors.append(f'{name}: no cover_hits.bin in {d}')
            continue
        h = load_hits(d)
        outside = h - m.block_set
        if not h:
            errors.append(f'{name}: empty hit list (spike not armed?)')
        if outside:
            errors.append(f'{name}: {len(outside)} hits are not block starts of the map')
        held = 'heldout' in name or 'heldout' in d
        runs.append({'name': name, 'dir': d, 'hits': h & m.block_set, 'heldout': held,
                     'cmds': commands_in_trace(d)})
    if not runs:
        print('\n'.join(errors) or 'no runs')
        return 2

    union = set().union(*(r['hits'] for r in runs))
    pub = set().union(*(r['hits'] for r in runs if not r['heldout'])) if any(not r['heldout'] for r in runs) else set()
    hel = set().union(*(r['hits'] for r in runs if r['heldout'])) if any(r['heldout'] for r in runs) else set()
    L = []
    L.append(f'coverage of {len(runs)} runs against {a.map} '
             f'({len(m.blocks)} blocks, {sum(m.total.values())} instructions)')
    L.append('PROJECTION  one-shot breakpoint per block start; instruction-weighted by the static map v2.')
    L.append('            Code outside the map (none observed) would be invisible.')
    L.append('')
    L.append(f"{'section':8s} {'blocks':>17s} {'':6s} {'instructions':>17s}")
    res = {'sections': {}, 'runs': [], 'public': {}, 'heldout': {}}
    for s in SECTIONS:
        hb = sum(1 for b in union if section_of(b) == s)
        hi = instr(m, union, s)
        L.append(f'{s:8s} {hb:7d} / {m.total_blocks[s]:7d} {pct(hb, m.total_blocks[s])} '
                 f'{hi:7d} / {m.total[s]:7d} {pct(hi, m.total[s])}')
        res['sections'][s] = {'blocks': hb, 'blocks_total': m.total_blocks[s], 'instructions': hi,
                              'instructions_total': m.total[s]}
    tot_i = instr(m, union)
    L.append(f"{'all':8s} {len(union):7d} / {len(m.blocks):7d} {pct(len(union), len(m.blocks))} "
             f'{tot_i:7d} / {sum(m.total.values()):7d} {pct(tot_i, sum(m.total.values()))}')

    fset = set(m.functions)
    fent = union & fset
    L.append(f'functions entered: {len(fent)} / {len(fset)} {pct(len(fent), len(fset))}')
    handler_hit = [i for i, h in enumerate(m.commands) if h in union]
    L.append(f'command handlers entered: {len(handler_hit)} / {len(m.commands)}: {handler_hit}')
    res['functions_entered'] = len(fent)
    res['handlers_entered'] = handler_hit

    cs = m.total['CODESEG']
    if not a.quiet_runs:
        L.append('')
        L.append('per run (CODESEG instructions; unique = reached by no other run)')
        for r in runs:
            others = set().union(*(o['hits'] for o in runs if o is not r)) if len(runs) > 1 else set()
            ci = instr(m, r['hits'], 'CODESEG')
            ui = instr(m, r['hits'] - others, 'CODESEG')
            cc = Counter((c[0], c[1]) for c in r['cmds'])
            cstr = ' '.join(f"{k[0]}{'a' if k[1] else 'q'}x{v}" for k, v in sorted(cc.items()))
            L.append(f"  {'H' if r['heldout'] else 'P'} {r['name']:40s} {ci:7d} {pct(ci, cs)}  unique {ui:6d}  cmds: {cstr}")
            res['runs'].append({'name': r['name'], 'heldout': r['heldout'], 'codeseg': ci, 'unique': ui,
                                'commands': {f'{k[0]}{"a" if k[1] else "q"}': v for k, v in cc.items()}})
    L.append('')
    for nm, S, O in (('public', pub, hel), ('held-out', hel, pub)):
        ci = instr(m, S, 'CODESEG')
        only = instr(m, S - O, 'CODESEG')
        L.append(f'{nm:9s} union CODESEG {ci:7d} {pct(ci, cs)}; reaches {only} instructions '
                 f'({len(S - O)} blocks) the other split does not')
        res['public' if nm == 'public' else 'heldout'] = {'codeseg': ci, 'only': only}

    allc = defaultdict(lambda: [0, 0, 0])   # id -> [queries, applies, injected successes]
    for r in runs:
        for c in r['cmds']:
            allc[c[0]][c[1]] += 1
            if c[2]:
                allc[c[0]][2] += 1
    L.append('')
    L.append(f'commands dispatched (trace): {len(allc)} distinct ids: '
             + ' '.join(f'{k}(q{v[0]}/a{v[1]})' for k, v in sorted(allc.items())))
    res['commands_dispatched'] = {k: v for k, v in allc.items()}

    if a.top:
        un = defaultdict(int)
        size = defaultdict(int)
        for b in m.blocks:
            if section_of(b) != 'CODESEG' or b not in m.func_of:
                continue
            f = m.func_of[b]
            size[f] += m.weight[b]
            if b not in union:
                un[f] += m.weight[b]
        L.append('')
        L.append(f'largest unexecuted CODESEG functions (by unexecuted instructions; extent = to next entry)')
        for f, n in sorted(un.items(), key=lambda kv: -kv[1])[:a.top]:
            L.append(f"  {f:#08x}  {n:6d} / {size[f]:6d} unexecuted  {'entered' if f in union else 'never entered'}")
    if errors:
        L.append('')
        L.extend('ERROR ' + e for e in errors)
    print('\n'.join(L))
    if a.json:
        with open(a.json, 'w') as f:
            json.dump(res, f, indent=1)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
