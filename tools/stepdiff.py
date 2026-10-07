#!/usr/bin/env python3
"""Register captures (istep_regs.bin, RCTHOOK_SPIKE=istep=A:B,regs; format in oracle/README.md,
"Register capture"), from the oracle (one record per instruction) or from the lift (one per
block entry).

  stepdiff.py summary FILE
  stepdiff.py dump    FILE [--from N] [--count N]
  stepdiff.py diff    ORACLE LIFT [--starts BLOCKS.bin] [--flags-mask 0xcd5] [--no-writes]
                      [--wmem LO-HI] [--exe rct.exe] [--context N]
        first divergence of LIFT from ORACLE. The oracle stream is reduced to the R records whose
        eip is a block start (the eips occurring in LIFT, or the addresses in --starts), rep
        iterations collapsed. Compared per block: eip, T markers, registers, eflags under the
        mask, and the memory effect (last value written to each byte). Registers an OS call
        leaves undefined (ecx, edx, eflags after any O; eax after a void import) are not compared
        in the block after the call (they become the baseline) and are compared again once an
        instruction changes them in either stream. With osmap.txt files (next to the captures, or
        --osmap-oracle/--osmap-lift), function values and COM object pointers the OS chose are
        compared by name (fn:ReadFile, obj:IDirectDraw#0) in registers and 4-byte writes.
  stepdiff.py verify  ORACLE DUMP_AT_A DUMP_AT_B+1
        completeness of the write capture: apply the recorded writes to the state dump taken at
        tick A ("tick A dump") and compare with the dump at tick B+1. Differences are writes the
        capture missed or writes made by OS code.
  stepdiff.py selftest ORACLE [--starts BLOCKS.bin] [--limit N]
        the comparator's own check: a lift-like stream synthesised from ORACLE (block entries
        only) must compare IDENTICAL, and five mutants of it (flipped CF, changed eax, changed
        written value, changed write address, dropped block entry) must each be reported at the
        mutated block.
"""
import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAGIC = 0x50545352
REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
STATE = ((0x5F4000, 0x9A161C), (0x9A2000, 0x9B2301))


# ------------------------------------------------------------------ reading / writing

def read(path, limit=None):
    """-> (flags, [records]); records: ('R', rflags, eip, regs8, eflags) | ('W', size, addr, value)
    | ('T', tick) | ('O', slot, ret)"""
    with open(path, 'rb') as f:
        data = f.read()
    magic, ver, flags, _ = struct.unpack_from('<4I', data, 0)
    if magic != MAGIC or ver != 1:
        raise SystemExit(f'{path}: not a version-1 register capture')
    out, off, n = [], 16, len(data)
    unpack = struct.unpack_from
    while off < n:
        tag = data[off]
        if tag == 0x52:
            v = unpack('<11I', data, off)
            out.append(('R', (v[0] >> 8) & 0xFF, v[1], v[2:10], v[10]))
            off += 44
        elif tag == 0x57:
            v = unpack('<3I', data, off)
            out.append(('W', (v[0] >> 8) & 0xFF, v[1], v[2]))
            off += 12
        elif tag == 0x54:
            out.append(('T', unpack('<I', data, off + 4)[0]))
            off += 8
        elif tag == 0x4F:
            v = unpack('<3I', data, off)
            out.append(('O', v[1], v[2]))
            off += 12
        else:
            raise SystemExit(f'{path}: bad record tag {tag:#x} at offset {off}')
        if limit and len(out) >= limit:
            break
    return flags, out


def write(path, flags, recs):
    b = bytearray(struct.pack('<4I', MAGIC, 1, flags, 0))
    for r in recs:
        if r[0] == 'R':
            b += struct.pack('<11I', 0x52 | r[1] << 8, r[2], *r[3], r[4])
        elif r[0] == 'W':
            b += struct.pack('<3I', 0x57 | r[1] << 8, r[2], r[3])
        elif r[0] == 'T':
            b += struct.pack('<2I', 0x54, r[1])
        else:
            b += struct.pack('<3I', 0x4F, r[1], r[2])
    with open(path, 'wb') as f:
        f.write(b)


def fmt(r):
    if r is None:
        return '<end>'
    if r[0] == 'R':
        fl = ''.join(c for c, bit in (('rep', 1), ('after-os', 2), ('entry', 4)) if r[1] & bit)
        return (f'R {r[2]:08x} ' + ' '.join(f'{n}={v:08x}' for n, v in zip(REGS, r[3])) +
                f' efl={r[4]:08x}' + (f' [{fl}]' if fl else ''))
    if r[0] == 'W':
        return f'W [{r[2]:08x}] = {r[3]:0{2 * r[1]}x} ({r[1]})'
    if r[0] == 'T':
        return f'T tick {r[1]}'
    return f'O slot={r[1]:08x} ret={r[2]:08x}'


# ------------------------------------------------------------------ imports (void returns)

def void_slots(exe):
    """IAT slot addresses of imports whose signature returns void (apisig.txt)"""
    try:
        sys.path.insert(0, HERE)
        import apitrace
        sigs = apitrace.Sigs()
        d = open(exe, 'rb').read()
    except (OSError, ImportError):
        return set()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec, opt = struct.unpack_from('<H', d, pe + 6)[0], struct.unpack_from('<H', d, pe + 20)[0]
    base = struct.unpack_from('<I', d, pe + 24 + 28)[0]
    imp_rva = struct.unpack_from('<I', d, pe + 24 + 104)[0]
    secs = [struct.unpack_from('<8x4I', d, pe + 24 + opt + 40 * i) for i in range(nsec)]

    def off(rva):
        for vsize, va, rsize, raw in secs:
            if va <= rva < va + max(vsize, rsize):
                return raw + rva - va
        raise ValueError(rva)

    out, p = set(), off(imp_rva)
    while True:
        oft, _, _, name, ft = struct.unpack_from('<5I', d, p)
        if not name:
            break
        i = 0
        while True:
            t = struct.unpack_from('<I', d, off(oft or ft) + 4 * i)[0]
            if not t:
                break
            if not t & 0x80000000:
                q = off(t) + 2
                nm = d[q:d.index(b'\0', q)].decode()
                s = sigs.get(nm)
                if s and s[1].base == 'v':
                    out.add(base + ft + 4 * i)
            i += 1
        p += 20
    return out


# ------------------------------------------------------------------ comparison

class Block:
    __slots__ = ('r', 'writes', 'os', 'void', 'idx', 'tick', 'frame')


def blocks(recs, starts, collapse_rep=True):
    """group a stream into block entries: each yields (kind, Block|tick)"""
    cur = None
    pending_os, pending_void = False, False
    tick = None
    voids = blocks.voids
    for i, r in enumerate(recs):
        t = r[0]
        if t == 'R':
            if (starts is not None and r[2] not in starts) or (collapse_rep and r[1] & 1):
                continue
            if cur is not None:
                yield 'R', cur
            cur = Block()
            cur.r, cur.writes, cur.os, cur.void, cur.idx, cur.tick = r, [], pending_os, pending_void, i, tick
            pending_os = pending_void = False
        elif t == 'W':
            if cur is not None:
                cur.writes.append(r)
        elif t == 'O':
            pending_os = True
            pending_void = pending_void or r[1] in voids
        elif t == 'T':
            if cur is not None:
                yield 'R', cur
                cur = None
            tick = r[1]
            yield 'T', r[1]
    if cur is not None:
        yield 'R', cur


blocks.voids = set()


def load_osmap(path):
    """osmap.txt (oracle RCTHOOK_SPIKE=istep/apitrace, or the lift's): value -> symbol"""
    m = {}
    if not path:
        return m
    nobj = {}
    for ln in open(path):
        p = ln.split()
        if not p or p[0].startswith('#'):
            continue
        if p[0] == 'fn':
            m[int(p[1], 16)] = 'fn:' + p[3]
        elif p[0] == 'obj':
            k = nobj.get(p[2], 0)
            nobj[p[2]] = k + 1
            m.setdefault(int(p[1], 16), f'obj:{p[2]}#{k}')
    return m


class SymMap:
    """maps OS-chosen values of both streams onto shared symbols (encoded as 0xEE000000 + index)"""
    def __init__(self, omap, lmap):
        syms = sorted(set(omap.values()) | set(lmap.values()))
        idx = {s: 0xEE000000 + i for i, s in enumerate(syms)}
        self.o = {v: idx[s] for v, s in omap.items()}
        self.l = {v: idx[s] for v, s in lmap.items()}

    def oracle(self, v):
        return self.o.get(v, v)

    def lift(self, v):
        return self.l.get(v, v)


def effect(writes, wr, frame=None, lift=False, sym=None):
    """last byte written per address; inside a guest-entry frame, lift stack addresses and
    stack-pointer values are rebased onto the oracle's stack"""
    m = {}
    for _, size, addr, val in writes:
        if frame and lift:
            if frame.in_lift_stack(addr):
                addr -= frame.delta
            if size == 4 and frame.in_lift_stack(val):
                val = (val - frame.delta) & 0xFFFFFFFF
        if sym and size == 4:
            val = sym.lift(val) if lift else sym.oracle(val)
        if wr and not (wr[0] <= addr < wr[1]):
            continue
        for k in range(size):
            m[addr + k] = (val >> (8 * k)) & 0xFF
    return m


class Frame:
    """game code entered from outside (rflags 4 or 8): the two stacks differ by a constant there"""
    def __init__(self, o_esp, l_esp, callback):
        self.o_esp, self.l_esp, self.delta, self.callback = o_esp, l_esp, (l_esp - o_esp) & 0xFFFFFFFF, callback

    def in_lift_stack(self, v):
        return self.delta and self.l_esp - 0x100000 <= v <= self.l_esp + 0x1000


def compare(orec, lrec, starts=None, mask=0xCD5, writes=True, wr=None, context=8, out=sys.stdout, sym=None):
    if starts is None:
        starts = {r[2] for r in lrec if r[0] == 'R'}
    go, gl = blocks(orec, starts), blocks(lrec, None, collapse_rep=False)
    tainted = set()
    frames = []
    prev_o = prev_l = None
    hist = []
    n = 0
    ncmp = {'blocks': 0, 'regs': 0, 'writes': 0, 'ticks': 0}
    while True:
        a, b = next(go, None), next(gl, None)
        if a is None and b is None:
            print(f'IDENTICAL: {ncmp["blocks"]} block entries, {ncmp["ticks"]} ticks, {ncmp["regs"]} register '
                  f'comparisons, {ncmp["writes"]} written bytes compared', file=out)
            return 0, ncmp

        def fail(why, detail=()):
            print(f'FIRST DIVERGENCE at block entry {n} ({why})', file=out)
            for h in hist[-context:]:
                print(f'    {h}', file=out)
            for d in detail:
                print(f'  {d}', file=out)
            return 1, dict(ncmp, index=n, why=why)

        if a is None or b is None or a[0] != b[0]:
            return fail('stream structure', [f'oracle: {a[0] + " " + (fmt(a[1].r) if a[0] == "R" else str(a[1])) if a else "<end>"}',
                                             f'lift:   {b[0] + " " + (fmt(b[1].r) if b[0] == "R" else str(b[1])) if b else "<end>"}'])
        if a[0] == 'T':
            if a[1] != b[1]:
                return fail('tick marker', [f'oracle: T {a[1]}', f'lift:   T {b[1]}'])
            ncmp['ticks'] += 1
            hist.append(f'T {a[1]}')
            continue
        ob, lb = a[1], b[1]
        ro, rl = ob.r, lb.r
        # memory effect of the previous block
        if writes and prev_o is not None:
            fr = getattr(prev_o, 'frame', None)
            eo, el = effect(prev_o.writes, wr, sym=sym), effect(prev_l.writes, wr, fr, True, sym=sym)
            ncmp['writes'] += len(eo)
            if eo != el:
                diff = sorted(set(eo) | set(el))
                bad = [x for x in diff if eo.get(x) != el.get(x)]
                det = [f'block {prev_o.r[2]:08x}: {len(bad)} bytes differ, first at {bad[0]:08x}: '
                       f'oracle {eo.get(bad[0], "none")} lift {el.get(bad[0], "none")}']
                det += [f'oracle writes: ' + ', '.join(fmt(w) for w in prev_o.writes[:12])]
                det += [f'lift writes:   ' + ', '.join(fmt(w) for w in prev_l.writes[:12])]
                return fail('memory effect', det)
        if ro[2] != rl[2]:
            return fail('eip', [f'oracle: {fmt(ro)}', f'lift:   {fmt(rl)}'])
        baseline = set()
        if ob.os or lb.os:
            # registers an OS call leaves undefined: this block's values are the new baseline;
            # they are compared again once an instruction changes them in either stream
            baseline = {1, 2, 8} | ({0} if (ob.void or lb.void) else set())
            tainted |= baseline
        while frames and ro[3][4] > frames[-1].o_esp:          # returned out of the entered code
            frames.pop()
        if ro[1] & 12:
            frames.append(Frame(ro[3][4], rl[3][4], bool(ro[1] & 8)))
            if ro[1] & 8:      # the OS's registers: only the stack arguments are defined
                tainted |= {0, 1, 2, 3, 5, 6, 7, 8}
        fr = frames[-1] if frames else None
        ob.frame = lb.frame = fr
        diffs = []
        for i in range(9):
            vo = ro[3][i] if i < 8 else ro[4]
            vl = rl[3][i] if i < 8 else rl[4]
            if fr and i < 8 and fr.in_lift_stack(vl):
                vl = (vl - fr.delta) & 0xFFFFFFFF
            if sym and i < 8:
                vo, vl = sym.oracle(vo), sym.lift(vl)
            if i in baseline:
                continue
            if i in tainted:
                po = prev_o.r[3][i] if (prev_o and i < 8) else (prev_o.r[4] if prev_o else None)
                pl = prev_l.r[3][i] if (prev_l and i < 8) else (prev_l.r[4] if prev_l else None)
                raw_l = rl[3][i] if i < 8 else rl[4]      # unchanged in both streams: still undefined
                if vo == po and raw_l == pl:
                    continue
                tainted.discard(i)
            if i == 8:
                vo, vl = vo & mask, vl & mask
            ncmp['regs'] += 1
            if vo != vl:
                diffs.append(f'{REGS[i] if i < 8 else "eflags"}: oracle {vo:08x} lift {vl:08x}')
        if diffs:
            return fail('registers', [f'oracle: {fmt(ro)}', f'lift:   {fmt(rl)}'] + diffs)
        ncmp['blocks'] += 1
        hist.append(fmt(ro))
        if len(hist) > 64:
            del hist[:32]
        prev_o, prev_l = ob, lb
        n += 1


# ------------------------------------------------------------------ commands

def cmd_summary(path):
    flags, recs = read(path)
    from collections import Counter
    c = Counter(r[0] for r in recs)
    eips = {r[2] for r in recs if r[0] == 'R'}
    ticks = [r[1] for r in recs if r[0] == 'T']
    print(f'{path}: {"per instruction (oracle)" if flags & 1 else "per block entry (lift)"}')
    print(f'  records: R {c["R"]}  W {c["W"]}  T {c["T"]}  O {c["O"]}; distinct eips {len(eips)}')
    print(f'  rep iterations {sum(1 for r in recs if r[0] == "R" and r[1] & 1)}, after-os {sum(1 for r in recs if r[0] == "R" and r[1] & 2)}, '
          f'entries from outside {sum(1 for r in recs if r[0] == "R" and r[1] & 4)}')
    if ticks:
        print(f'  ticks {ticks[0]}..{ticks[-1]}')
    per, cur = [], None
    for r in recs:
        if r[0] == 'T':
            if cur is not None:
                per.append(cur)
            cur = [r[1], 0]
        elif r[0] == 'R' and cur is not None and not r[1] & 1:
            cur[1] += 1
    if cur:
        per.append(cur)
    for t, k in per:
        print(f'  tick {t}: {k} instructions')


def cmd_dump(path, start, count):
    _, recs = read(path)
    for r in recs[start:start + count]:
        print(fmt(r))


def load_starts(path):
    if not path:
        return None
    d = open(path, 'rb').read()
    return set(struct.unpack(f'<{len(d) // 4}I', d))


def cmd_diff(a, b, starts, mask, writes, wr, exe, context, osmap_o=None, osmap_l=None):
    blocks.voids = void_slots(exe) if exe and os.path.exists(exe) else set()
    _, ro = read(a)
    _, rl = read(b)
    if osmap_o is None and os.path.exists(os.path.join(os.path.dirname(a), 'osmap.txt')):
        osmap_o = os.path.join(os.path.dirname(a), 'osmap.txt')
    if osmap_l is None and os.path.exists(os.path.join(os.path.dirname(b), 'osmap.txt')):
        osmap_l = os.path.join(os.path.dirname(b), 'osmap.txt')
    sym = SymMap(load_osmap(osmap_o), load_osmap(osmap_l)) if (osmap_o or osmap_l) else None
    rc, _ = compare(ro, rl, load_starts(starts), mask, writes, wr, context, sym=sym)
    return rc


def cmd_verify(path, d0, d1):
    _, recs = read(path)
    a, b = bytearray(open(d0, 'rb').read()), open(d1, 'rb').read()
    n1 = STATE[0][1] - STATE[0][0]

    def off(addr):
        for i, (lo, hi) in enumerate(STATE):
            if lo <= addr < hi:
                return addr - lo + (n1 if i else 0)
        return None

    applied = outside = 0
    for r in recs:
        if r[0] != 'W':
            continue
        for k in range(r[1]):
            o = off(r[2] + k)
            if o is None:
                outside += 1
                continue
            a[o] = (r[3] >> (8 * k)) & 0xFF
            applied += 1
    bad, i = [], 0
    while i < len(a):
        if a[i] != b[i]:
            j = i
            while j < len(a) and a[j] != b[j]:
                j += 1
            bad.append((i, j))
            i = j
        else:
            i += 1

    def va(o):
        return STATE[0][0] + o if o < n1 else STATE[1][0] + o - n1
    print(f'{applied} written bytes applied inside the state, {outside} outside (stack, heap, .data)')
    nbytes = sum(j - i for i, j in bad)
    print(f'{len(bad)} ranges ({nbytes} bytes) differ between the replayed and the real end state')
    for i, j in bad[:20]:
        print(f'  {va(i):08x}..{va(j):08x} replayed {a[i:min(j, i + 8)].hex()} real {b[i:min(j, i + 8)].hex()}')
    return 0 if not bad else 1


def synth_lift(recs, starts):
    """a lift-like stream: R only at block starts (no rep iterations), all W/T/O"""
    out = []
    for r in recs:
        if r[0] == 'R':
            if r[2] in starts and not r[1] & 1:
                out.append(('R', 0, r[2], r[3], r[4]))
        else:
            out.append(r)
    return out


def cmd_selftest(path, starts_path, limit):
    _, recs = read(path, limit)
    starts = load_starts(starts_path)
    if starts is None:
        # without a code map: block starts = first instruction after any control transfer target,
        # approximated by the eips following an O or a non-sequential eip
        starts = set()
        prev = None
        for r in recs:
            if r[0] == 'R':
                if prev is None or not (0 < r[2] - prev <= 15):
                    starts.add(r[2])
                prev = r[2]
    lift = synth_lift(recs, starts)
    starts_used = {r[2] for r in lift if r[0] == 'R'}
    import io
    res = []
    sink = io.StringIO()
    rc, n = compare(recs, lift, starts_used, out=sink)
    res.append(('clean synthesised lift', rc == 0, sink.getvalue().strip().splitlines()[0]))
    if rc != 0:
        print(sink.getvalue())
    # the host enters game code (script actions, window procedure) on its own stack: shift it
    shifted, frames_, nshift = [], [], 0
    D = 0x2340
    def sh(v, lo):
        return (v + D) & 0xFFFFFFFF if lo - 0x100000 <= v <= lo + 0x1000 else v
    entries = {i for i, r in enumerate(recs) if r[0] == 'R' and r[1] & 12}
    oi = 0
    for r in lift:
        if r[0] == 'R':
            while frames_ and r[3][4] > frames_[-1]:
                frames_.pop()
            # synthesised R records keep oracle order; recover the entry flag from the oracle stream
            while oi < len(recs) and not (recs[oi][0] == 'R' and recs[oi][2] == r[2] and not recs[oi][1] & 1):
                oi += 1
            if oi in entries:
                frames_.append(r[3][4])
            oi += 1
            if frames_:
                lo = frames_[0]
                r = ('R', 0, r[2], tuple(sh(v, lo) for v in r[3]), r[4])
                nshift += 1
        elif r[0] == 'W' and frames_:
            lo = frames_[0]
            r = ('W', r[1], sh(r[2], lo), sh(r[3], lo) if r[1] == 4 else r[3])
        shifted.append(r)
    sink = io.StringIO()
    rc, _ = compare(recs, shifted, starts_used, out=sink)
    res.append((f'entered code on a shifted host stack ({nshift} block entries shifted)', rc == 0 and nshift > 0,
                sink.getvalue().strip().splitlines()[0]))
    ridx = [i for i, r in enumerate(lift) if r[0] == 'R']
    widx = [i for i, r in enumerate(lift) if r[0] == 'W' and STATE[0][0] <= r[2] < STATE[0][1]]
    k = ridx[len(ridx) // 2]
    w = widx[len(widx) // 2] if widx else None

    def mutant(name, fn):
        m = list(lift)
        fn(m)
        s = io.StringIO()
        rc, info = compare(recs, m, starts_used, out=s)
        res.append((name, rc != 0, s.getvalue().strip().splitlines()[0]))

    mutant('CF flipped at one block entry', lambda m: m.__setitem__(k, ('R', 0, m[k][2], m[k][3], m[k][4] ^ 1)))
    mutant('eax changed at one block entry', lambda m: m.__setitem__(k, ('R', 0, m[k][2], (m[k][3][0] ^ 0x100,) + tuple(m[k][3][1:]), m[k][4])))
    if w is not None:
        mutant('one DATASEG write value changed', lambda m: m.__setitem__(w, ('W', m[w][1], m[w][2], m[w][3] ^ 1)))
        mutant('one DATASEG write address changed', lambda m: m.__setitem__(w, ('W', m[w][1], m[w][2] + 0x40, m[w][3])))
    mutant('one block entry dropped', lambda m: m.pop(k))
    ok = True
    for name, good, line in res:
        print(f'  {"PASS" if good else "FAIL"}  {name}: {line}')
        ok = ok and good
    print(f'{len(recs)} oracle records, {len(ridx)} synthesised block entries, {len(starts_used)} block starts')
    print('SELFTEST ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('summary')
    s.add_argument('file')
    d = sub.add_parser('dump')
    d.add_argument('file')
    d.add_argument('--from', dest='start', type=int, default=0)
    d.add_argument('--count', type=int, default=50)
    f = sub.add_parser('diff')
    f.add_argument('oracle')
    f.add_argument('lift')
    f.add_argument('--starts')
    f.add_argument('--flags-mask', type=lambda x: int(x, 0), default=0xCD5)
    f.add_argument('--no-writes', action='store_true')
    f.add_argument('--wmem')
    f.add_argument('--exe', default=os.path.join(ROOT, 'game', 'cd', 'English', 'rct.exe'))
    f.add_argument('--context', type=int, default=8)
    f.add_argument('--osmap-oracle', help='osmap.txt of the oracle run (default: next to ORACLE)')
    f.add_argument('--osmap-lift', help="the lift's osmap.txt (default: next to LIFT)")
    v = sub.add_parser('verify')
    v.add_argument('file')
    v.add_argument('dump_a')
    v.add_argument('dump_b')
    t = sub.add_parser('selftest')
    t.add_argument('file')
    t.add_argument('--starts')
    t.add_argument('--limit', type=int, default=3_000_000)
    a = ap.parse_args(argv[1:])
    try:
        if a.cmd == 'summary':
            cmd_summary(a.file)
            return 0
        if a.cmd == 'dump':
            cmd_dump(a.file, a.start, a.count)
            return 0
        if a.cmd == 'diff':
            wr = tuple(int(x, 0) for x in a.wmem.split('-')) if a.wmem else None
            return cmd_diff(a.oracle, a.lift, a.starts, a.flags_mask, not a.no_writes, wr, a.exe, a.context,
                            a.osmap_oracle, a.osmap_lift)
        if a.cmd == 'verify':
            return cmd_verify(a.file, a.dump_a, a.dump_b)
        if a.cmd == 'selftest':
            return cmd_selftest(a.file, a.starts, a.limit)
    except BrokenPipeError:
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
