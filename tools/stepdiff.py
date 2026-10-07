#!/usr/bin/env python3
"""Register captures (istep_regs.bin, RCTHOOK_SPIKE=istep=A:B,regs; format in oracle/README.md,
"Register capture"), from the oracle (one record per instruction) or from the lift (one per
block entry).

  stepdiff.py summary FILE
  stepdiff.py dump    FILE [--from N] [--count N]
  stepdiff.py diff    ORACLE LIFT [--starts BLOCKS.bin] [--flags-mask 0xcd5] [--no-writes]
                      [--wmem LO-HI] [--exe rct.exe] [--context N]
        first divergence of LIFT from ORACLE. The oracle stream is reduced to the R records whose
        eip is a block start the lift recorded (--starts FILE is only cross-checked against them),
        rep iterations collapsed. Compared per block: eip, T markers, registers, eflags under the
        mask, and the memory effect (last value written to each byte). Registers an OS call
        leaves undefined (ecx, edx, eflags after any O; eax after a void import) are not compared
        in the block after the call (they become the baseline) and are compared again once an
        instruction changes them in either stream. With osmap.txt files (next to the captures, or
        --osmap-oracle/--osmap-lift), OS-chosen values (function values, COM objects, vtables) are
        compared by name, bilaterally: in registers and 4-byte writes, two different values are
        equal only if BOTH are OS values of the same name (fn:ReadFile, vtbl:IDirectDraw#0).
  stepdiff.py verify  ORACLE DUMP_AT_A DUMP_AT_B+1
        completeness of the write capture: apply the recorded writes to the state dump taken at
        tick A ("tick A dump") and compare with the dump at tick B+1. Differences are writes the
        capture missed or writes made by OS code.
  stepdiff.py selftest ORACLE [--starts BLOCKS.bin] [--limit N]
        the comparator's own check: a lift-like stream synthesised from ORACLE (block entries
        only) must compare IDENTICAL, also with the entered code on a shifted host stack and
        (with ORACLE's osmap.txt) with every OS value renamed to a host address, and with game
        values that equal an oracle thunk or a host address on both sides; mutants must each be
        reported: flipped CF, changed eax, changed written value, changed write address, dropped
        block entry, wrong function value, an OS value on one side only.
"""
import argparse
import os
import re
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
        elif p[0] in ('obj', 'vtbl'):
            k = nobj.get((p[0], p[2]), 0)
            nobj[(p[0], p[2])] = k + 1
            m.setdefault(int(p[1], 16), f'{p[0]}:{p[2]}#{k}')
    return m


class SymMap:
    """OS-chosen values (osmap.txt of each side): function values, COM objects and vtables.

    Bilateral rule: two values are equal if they are equal, or if BOTH are OS values with the same
    name (oracle fn:ReadFile = thunk 5ea70560, lift fn:ReadFile = fff00560). A value that is an OS
    value on one side only is compared raw: game data that happens to equal an address in one
    side's map (a sprite flag 0x20000000, a constant 0xfff00040) is never renamed. Mismatches that
    involve an OS value on either side are annotated "OS-derived?"."""
    def __init__(self, omap, lmap):
        self.o, self.l = omap, lmap

    def same(self, vo, vl):
        s = self.o.get(vo)
        return s is not None and s == self.l.get(vl)

    def note(self, vo, vl):
        so, sl = self.o.get(vo), self.l.get(vl)
        return f' (OS-derived? oracle {so or "-"}, lift {sl or "-"})' if (so or sl) else ''


def effect(writes, wr, frame=None, lift=False):
    """last byte written per address; inside a guest-entry frame, lift stack addresses and
    stack-pointer values are rebased onto the oracle's stack"""
    m = {}
    for _, size, addr, val in writes:
        if frame and lift:
            if frame.in_lift_stack(addr):
                addr -= frame.delta
            if size == 4 and frame.in_lift_stack(val):
                val = (val - frame.delta) & 0xFFFFFFFF
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
    # the oracle is reduced to the block starts the LIFT recorded: a code map (--starts) may differ
    # from the lift's own map version, which would drop or add oracle entries the lift never emits
    lift_starts = {r[2] for r in lrec if r[0] == 'R'}
    if starts is not None:
        extra = lift_starts - starts
        if extra:
            print(f'note: {len(extra)} lift block entries are not in --starts (first {min(extra):08x}); '
                  f'the lift\'s own block starts are used', file=out)
    starts = lift_starts
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
            eo, el = effect(prev_o.writes, wr), effect(prev_l.writes, wr, fr, True)
            if sym and eo != el:
                # bilateral OS values written as dwords: the oracle's and the lift's name the same thing
                for w in prev_l.writes:
                    if w[1] != 4:
                        continue
                    a = w[2] - fr.delta if (fr and fr.in_lift_stack(w[2])) else w[2]
                    bo = [eo.get(a + k) for k in range(4)]
                    bl = [el.get(a + k) for k in range(4)]
                    if None in bo or None in bl or bo == bl:
                        continue
                    vo = int.from_bytes(bytes(bo), 'little')
                    vl = int.from_bytes(bytes(bl), 'little')
                    if sym.same(vo, vl):
                        for k in range(4):
                            el[a + k] = eo[a + k]
            ncmp['writes'] += len(eo)
            if eo != el:
                diff = sorted(set(eo) | set(el))
                bad = [x for x in diff if eo.get(x) != el.get(x)]
                det = [f'block {prev_o.r[2]:08x}: {len(bad)} bytes differ, first at {bad[0]:08x}: '
                       f'oracle {eo.get(bad[0], "none")} lift {el.get(bad[0], "none")}']
                if sym:
                    a4 = bad[0] & ~3
                    bo = [eo.get(a4 + k) for k in range(4)]
                    bl = [el.get(a4 + k) for k in range(4)]
                    if None not in bo and None not in bl:
                        det[0] += sym.note(int.from_bytes(bytes(bo), 'little'), int.from_bytes(bytes(bl), 'little'))
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
            if sym and i < 8 and vo != vl and sym.same(vo, vl):
                vl = vo
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
                diffs.append(f'{REGS[i] if i < 8 else "eflags"}: oracle {vo:08x} lift {vl:08x}'
                             + (sym.note(vo, vl) if (sym and i < 8) else ''))
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


def synth_lift(recs, starts, src=None):
    """a lift-like stream: R only at block starts (no rep iterations), all W/T/O; src (a list)
    receives the oracle index of every record"""
    out = []
    for i, r in enumerate(recs):
        if r[0] == 'R':
            if r[2] in starts and not r[1] & 1:
                out.append(('R', 0, r[2], r[3], r[4]))
                if src is not None:
                    src.append(i)
        else:
            out.append(r)
            if src is not None:
                src.append(i)
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
    src = []
    lift = synth_lift(recs, starts, src)
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
    if nshift:
        res.append((f'entered code on a shifted host stack ({nshift} block entries shifted)', rc == 0,
                    sink.getvalue().strip().splitlines()[0]))
    else:
        print('  skip  entered code on a shifted host stack: the capture has no game code entered from outside')
    # OS values (osmap.txt next to the capture): renamed bilaterally, never by equality on one side
    omap_path = os.path.join(os.path.dirname(path), 'osmap.txt')
    if os.path.exists(omap_path):
        omap = load_osmap(omap_path)
        hostv = {}
        for i, v in enumerate(sorted(omap)):
            hostv[v] = (0xFFF00000 + 16 * i) if omap[v].startswith('fn:') else (0x00A00000 + 16 * i)
        lmap = {hostv[v]: omap[v] for v in omap}
        sym = SymMap(omap, lmap)

        def ren(v):
            return hostv.get(v, v)
        hl = []
        nren = 0
        for r in lift:
            if r[0] == 'R':
                regs = tuple(ren(v) for v in r[3])
                nren += sum(1 for a_, b_ in zip(r[3], regs) if a_ != b_)
                r = ('R', r[1], r[2], regs, r[4])
            elif r[0] == 'W' and r[1] == 4 and r[3] in hostv:
                r = ('W', 4, r[2], ren(r[3])); nren += 1
            hl.append(r)
        s_ = io.StringIO()
        rc, _ = compare(recs, hl, starts_used, out=s_, sym=sym)
        res.append((f'OS values renamed to host addresses ({nren} values)', rc == 0 and nren > 0, s_.getvalue().strip().splitlines()[0]))
        ri = [i for i, r in enumerate(hl) if r[0] == 'R']
        k2 = ri[len(ri) // 3]
        ok_idx = src[k2]
        thunk = next(v for v in sorted(omap) if omap[v].startswith('fn:'))
        hostval = hostv[thunk]

        def both(val, reg):
            o2, l2 = list(recs), list(hl)
            ro_ = o2[ok_idx]; o2[ok_idx] = ('R', ro_[1], ro_[2], tuple(val if j == reg else v for j, v in enumerate(ro_[3])), ro_[4])
            rl_ = l2[k2]; l2[k2] = ('R', rl_[1], rl_[2], tuple(val if j == reg else v for j, v in enumerate(rl_[3])), rl_[4])
            s2 = io.StringIO()
            rc2, _ = compare(o2, l2, starts_used, out=s2, sym=sym)
            return rc2, s2.getvalue().strip().splitlines()[0]
        rc, line = both(thunk, 3)
        res.append((f'game value equal to an oracle thunk ({thunk:08x}) on both sides', rc == 0, line))
        rc, line = both(hostval, 3)
        res.append((f'game value equal to a host address ({hostval:08x}) on both sides', rc == 0, line))
        o2, l2 = list(recs), list(hl)
        other = next(v for v in sorted(omap) if omap[v].startswith('fn:') and v != thunk)
        ro_ = o2[ok_idx]; o2[ok_idx] = ('R', ro_[1], ro_[2], (thunk,) + tuple(ro_[3][1:]), ro_[4])
        rl_ = l2[k2]; l2[k2] = ('R', rl_[1], rl_[2], (hostv[other],) + tuple(rl_[3][1:]), rl_[4])
        s2 = io.StringIO(); rc, _ = compare(o2, l2, starts_used, out=s2, sym=sym)
        res.append((f'wrong function value ({omap[thunk]} vs {omap[other]})', rc != 0, s2.getvalue().strip().splitlines()[0]))
        l2 = list(hl); rl_ = l2[k2]; l2[k2] = ('R', rl_[1], rl_[2], (thunk,) + tuple(rl_[3][1:]), rl_[4])
        o2 = list(recs); ro_ = o2[ok_idx]; o2[ok_idx] = ('R', ro_[1], ro_[2], (thunk,) + tuple(ro_[3][1:]), ro_[4])
        l2[k2] = ('R', rl_[1], rl_[2], (0x12345678,) + tuple(rl_[3][1:]), rl_[4])
        s2 = io.StringIO(); rc, _ = compare(o2, l2, starts_used, out=s2, sym=sym)
        res.append(('OS value on the oracle side only', rc != 0, s2.getvalue().strip().splitlines()[0]))
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


def expected_writes(ins, regs, nxt):
    """independent model (capstone) of the memory an instruction writes: [(addr, size)].
    regs: eax ecx edx ebx esp ebp esi edi before it; nxt: registers after it (for esp after pop)"""
    from capstone.x86 import X86_OP_MEM, X86_OP_REG
    import capstone as cs
    R = dict(zip(('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'), regs))
    name = ins.mnemonic.split()[-1]          # "rep movsd" -> movsd
    pre = set(ins.prefix)
    esp = R['esp']
    opsz = 2 if 0x66 in pre else 4

    def reg32(r):
        n = ins.reg_name(r)
        if n in R:
            return R[n]
        sub = {'ax': 'eax', 'cx': 'ecx', 'dx': 'edx', 'bx': 'ebx', 'sp': 'esp', 'bp': 'ebp', 'si': 'esi', 'di': 'edi'}
        if n in sub:
            return R[sub[n]] & 0xFFFF
        lo = {'al': 'eax', 'cl': 'ecx', 'dl': 'edx', 'bl': 'ebx'}
        hi = {'ah': 'eax', 'ch': 'ecx', 'dh': 'edx', 'bh': 'ebx'}
        if n in lo:
            return R[lo[n]] & 0xFF
        if n in hi:
            return (R[hi[n]] >> 8) & 0xFF
        return None

    def ea(op):
        m = op.mem
        if m.segment and ins.reg_name(m.segment) not in ('ds', 'es', 'ss', 'cs'):
            return None                     # fs: (TEB) not modelled here
        a = m.disp
        if m.base:
            v = reg32(m.base)
            if v is None:
                return None
            a += v
        if m.index:
            v = reg32(m.index)
            if v is None:
                return None
            a += v * m.scale
        return a & 0xFFFFFFFF

    if name in ('push', 'pushal', 'pushfd', 'pushf', 'pushaw', 'pusha', 'call'):
        n = {'pushal': 32, 'pusha': 32, 'pushaw': 16}.get(name, 4 if name == 'call' else opsz)
        if name == 'push' and ins.operands and ins.operands[0].type == X86_OP_REG and ins.operands[0].size == 2:
            n = 2
        return [(esp - n, n)]
    if name in ('stosb', 'stosw', 'stosd', 'movsb', 'movsw', 'movsd'):
        if (0xF3 in pre or 0xF2 in pre) and R['ecx'] == 0:
            return []
        return [(R['edi'], {'b': 1, 'w': 2, 'd': 4}[name[-1]])]
    if name == 'enter':
        return [(esp - 4, 4)]
    if name in ('bts', 'btr', 'btc') and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_MEM:
        a, size = ea(ins.operands[0]), ins.operands[0].size
        if a is None:
            return None
        if ins.operands[1].type == X86_OP_REG:
            off = reg32(ins.operands[1].reg)
            bits = size * 8
            off = off - (1 << bits) if off >= 1 << (bits - 1) else off     # signed bit offset
            a = (a + (off >> (3 + size.bit_length() - 1)) * size) & 0xFFFFFFFF
        return [(a, size)]
    out = []
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.access & cs.CS_AC_WRITE:
            a = ea(op)
            if a is None:
                return None
            if name == 'pop' and op.mem.base and ins.reg_name(op.mem.base) == 'esp':
                a = (a + opsz) & 0xFFFFFFFF
            out.append((a, op.size))
    return out


def cmd_audit(paths, show=12):
    """compare the oracle's recorded writes with an independent model, per instruction form"""
    try:
        import capstone as cs
    except ImportError:
        raise SystemExit('audit needs capstone (run with .venv/bin/python)')
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    md.detail = True
    img = open(os.path.join(ROOT, 'game', 'cd', 'English', 'rct.exe'), 'rb').read()
    pe = struct.unpack_from('<I', img, 0x3C)[0]
    nsec, opt = struct.unpack_from('<H', img, pe + 6)[0], struct.unpack_from('<H', img, pe + 20)[0]
    secs = [struct.unpack_from('<8x4I', img, pe + 24 + opt + 40 * i) for i in range(nsec)]

    def code(va, n=16):
        rva = va - 0x400000
        for vsize, sva, rsize, raw in secs:
            if sva <= rva < sva + max(vsize, rsize):
                return img[raw + rva - sva: raw + rva - sva + n]
        return b''
    cache = {}
    from collections import Counter, defaultdict
    forms, bad, examples = Counter(), Counter(), defaultdict(list)
    nins = 0
    for path in paths:
        _, recs = read(path)
        for i, r in enumerate(recs):
            if r[0] != 'R':
                continue
            j, ws = i + 1, []
            while j < len(recs) and recs[j][0] == 'W':
                ws.append(recs[j]); j += 1
            nxt = recs[j] if j < len(recs) and recs[j][0] == 'R' else None
            ins = cache.get(r[2])
            if ins is None:
                ins = next(md.disasm(code(r[2]), r[2]), None)
                cache[r[2]] = ins or False
            if not ins:
                continue
            exp = expected_writes(ins, r[3], nxt)
            nins += 1
            key = f'{ins.mnemonic} {re.sub(r"0x[0-9a-f]+", "N", ins.op_str)}'
            forms[key] += 1
            if exp is None or nxt is None:
                continue
            got = sorted((w[2], w[1]) for w in ws)
            # merge the recorded pieces (wide writes are split into <= 4-byte pieces)
            span = sorted(exp)
            ok = sum(n for _, n in got) == sum(n for _, n in span) and \
                (not got or (got[0][0] == span[0][0] if span else False)) and (bool(got) == bool(span))
            if not ok:
                bad[key] += 1
                if len(examples[key]) < 2:
                    examples[key].append(f'{r[2]:08x} {ins.mnemonic} {ins.op_str}: expected {[(hex(a), n) for a, n in span]}, '
                                         f'recorded {[(hex(a), n) for a, n in got]}')
    print(f'{nins} instructions, {len(forms)} instruction forms; {sum(bad.values())} executions of {len(bad)} forms disagree')
    for k, n in bad.most_common(show):
        print(f'  {n:8d} of {forms[k]:8d}  {k}')
        for e in examples[k]:
            print(f'           {e}')
    return 1 if bad else 0


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
    au = sub.add_parser('audit')
    au.add_argument('files', nargs='+')
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
        if a.cmd == 'audit':
            return cmd_audit(a.files)
        if a.cmd == 'selftest':
            return cmd_selftest(a.file, a.starts, a.limit)
    except BrokenPipeError:
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
