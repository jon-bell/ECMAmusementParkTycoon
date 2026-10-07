#!/usr/bin/env python3
"""Read, compare and summarise API traces (RCTHOOK_SPIKE=apitrace, or the JS host's equivalent).
Format: oracle/README.md, "API trace". Signatures: oracle/apisig.txt.

  apitrace.py dump    <apitrace.txt> [--canon] [--from N] [--count N] [--grep RE]
        readable form: one line per call (C and R merged when nothing happens in between),
        callbacks indented, structs decoded with field names
  apitrace.py diff    <a.txt> <b.txt> [--raw] [--ignore NAME,...] [--context N]
        first divergence after canonicalisation (exit 0 iff identical). Canonicalisation makes
        values the OS chooses comparable: handles are named by creation order (H1, H2, ...),
        pointers into OS-allocated memory become region+offset (A1+0x10), stack pointers become
        offsets from the record's esp (sp+0x1c), procedures returned by GetProcAddress become
        proc(name); the esp of calls made inside OS callbacks and the esp of callback entries are
        not compared. --raw compares the lines as written.
  apitrace.py shapes  <apitrace.txt>... [--canon] [--top N] [--name RE]
        per function: call count and the distinct (arguments -> results) shapes with counts
  apitrace.py check   <apitrace.txt>
        format check: every line parses, C/R and B/E nest, every name has a signature
"""
import argparse
import os
import re
import sys
from collections import Counter, OrderedDict, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SIGFILE = os.path.join(HERE, '..', 'oracle', 'apisig.txt')
IMG_LO, IMG_HI = 0x400000, 0x9BD000

# ------------------------------------------------------------------ signatures


class Kind:
    __slots__ = ('dir', 'base', 'sub', 'len', 'text', 'cond')

    def __init__(self, text, is_ret=False):
        self.text = text
        t = text
        self.cond = None
        if '?' in t and not is_ret:
            t, self.cond = t.split('?', 1)
        self.dir = 'in'
        if not is_ret:
            if t.startswith('io'):
                self.dir, t = 'io', t[2:]
            elif t.startswith('o'):
                self.dir, t = 'out', t[1:]
        self.len = None
        if '@' in t:
            t, self.len = t.split('@', 1)
        self.sub = None
        if ':' in t:
            t, self.sub = t.split(':', 1)
        self.base = t
        if self.base == 'x' and self.len is not None:
            self.base = 'hexbuf'


class Sigs:
    def __init__(self, path=SIGFILE):
        self.fn, self.cb, self.struct, self.iface, self.msg = {}, {}, {}, {}, {}
        for ln in open(path):
            # '#' starts a comment at line start or after whitespace (names contain '#')
            ln = re.sub(r'(^|\s)#.*', '', ln).split()
            if not ln:
                continue
            if ln[0] == 'struct':
                fields, off = [], 0
                for f in ln[2:]:
                    k, name = f.split(':')
                    size = int(k[1:])
                    fields.append((off, k[0], size, name))
                    off += size
                self.struct[ln[1]] = (off, fields)
            elif ln[0] == 'iface':
                self.iface[ln[1]] = ln[2:]
            elif ln[0] == 'msg':
                self.msg[int(ln[1], 0)] = (ln[2], ln[3])
            elif ln[0] == 'fn':
                self.fn[ln[1]] = (ln[2], Kind(ln[3], True), [Kind(k) for k in ln[4:]])
            elif ln[0] == 'cb':
                self.cb[ln[1]] = ('std', Kind(ln[2], True), [Kind(k) for k in ln[3:]])

    def get(self, name, callback=False):
        return (self.cb if callback else self.fn).get(name)


# ------------------------------------------------------------------ parsing


class Rec:
    __slots__ = ('t', 'frame', 'tick', 'depth', 'ret', 'esp', 'name', 'target', 'args', 'rv', 'outs', 'line', 'no')

    def __repr__(self):
        return self.line


def parse_line(line, no=0):
    line = line.rstrip('\n')
    if not line or line[0] == '#':
        return None
    p = line.split(' ')
    r = Rec()
    r.t, r.line, r.no = p[0], line, no
    r.ret = r.esp = r.target = r.rv = None
    r.frame = r.tick = None
    r.args, r.outs = [], []
    if r.t == 'C':
        r.frame, r.tick, r.depth, r.ret, r.esp = (int(x, 16) for x in p[1:6])
        r.name, r.args = p[6], p[7:]
    elif r.t == 'R':
        r.depth, r.name, r.rv, r.outs = int(p[1], 16), p[2], p[3], p[4:]
    elif r.t == 'B':
        r.frame, r.tick, r.depth = (int(x, 16) for x in p[1:4])
        r.name, r.target, r.esp, r.args = p[4], int(p[5], 16), int(p[6], 16), p[7:]
    elif r.t == 'E':
        r.depth, r.name, r.rv, r.outs = int(p[1], 16), p[2], p[3], p[4:]
    else:
        raise ValueError(f'line {no}: unknown record type {r.t!r}')
    return r


def records(path):
    with open(path, errors='replace') as f:
        for no, line in enumerate(f, 1):
            r = parse_line(line, no)
            if r:
                yield r


# ------------------------------------------------------------------ canonicalisation

CLOSERS = {  # function -> argument index (0-based) whose handle stops existing
    'CloseHandle': 0, 'FindClose': 0, 'RegCloseKey': 0, 'DeleteObject': 0, 'DeleteDC': 0,
    'DestroyWindow': 0, 'HeapDestroy': 0, 'FreeLibrary': 0, 'GlobalFree': 0, 'DestroyIcon': 0,
    'DestroyCursor': 0, 'mmioClose': 0, '_lclose': 0, 'ReleaseDC': 1,
}
FREERS = {'HeapFree': 2, 'VirtualFree': 0, 'UnmapViewOfFile': 0}
# window messages whose wParam / lParam carry a handle (canonicalised like handles)
MSG_HANDLES = {0x0006: (0, 1), 0x0007: (1, 0), 0x0008: (1, 0), 0x0014: (1, 0), 0x0030: (1, 0),
               0x0086: (0, 1), 0x0110: (1, 0), 0x0111: (0, 1), 0x0310: (1, 0), 0x0311: (1, 0),
               **{m: (1, 1) for m in range(0x0132, 0x0139)}}
# functions taking (..., msg, wParam, lParam): index of msg
MSG_CALLS = {'DefWindowProcA': 1, 'SendMessageA': 1, 'SendDlgItemMessageA': 2}


class Canon:
    """Maps OS-chosen values to names that two correct runs share."""

    def __init__(self, sigs):
        self.s = sigs
        self.h = {}          # raw handle -> name
        self.nh = 0
        self.regions = []    # [base, size, label]
        self.na = 0
        self.procs = {}      # raw -> proc(name)
        self.stack_top = None
        self.cb_depth = 0    # open callbacks (B without E)
        self.open = []       # open C/B records

    # -- values
    def handle(self, v, create=False):
        if v == 0:
            return '0'
        if v in self.procs:
            return self.procs[v]
        if create and v not in self.h:
            self.nh += 1
            self.h[v] = f'H{self.nh}'
        return self.h.get(v, f'h?{v:x}')

    def region(self, v, size, label='A'):
        self.na += 1
        name = f'{label}{self.na}'
        self.regions = [r for r in self.regions if not (r[0] <= v < r[0] + max(r[1], 1))]
        self.regions.append([v, size, name])
        return name

    def ptr(self, v, esp=None, in_callback_entry=False, from_os=False):
        """from_os: a value the OS produced (return, out-param, callback argument); one outside every
        known region points into OS-owned memory (Wine's process heap, ...) and is not compared"""
        if v == 0:
            return '0'
        if IMG_LO <= v < IMG_HI:
            return f'{v:x}'
        if v in self.procs:
            return self.procs[v]
        best = None
        for base, size, name in self.regions:
            if base <= v < base + (size or 0x2000000) and (best is None or base > best[0]):   # unknown size: 32 MiB
                best = (base, size, name)
        if best:
            return f'{best[2]}+{v - best[0]:x}'
        if self.stack_top is not None and self.stack_top - 0x200000 <= v < self.stack_top + 0x10000:
            if in_callback_entry or esp is None:
                return 'stk'
            d = v - esp
            return f'sp+{d:x}' if d >= 0 else f'sp-{-d:x}'
        if v in self.h:
            return self.h[v]
        return 'os' if from_os else f'?{v:x}'

    def hexstruct(self, sname, hexs, esp, cbentry, from_os=False):
        st = self.s.struct.get(sname)
        if not st or len(hexs) != 2 * st[0]:
            return '{' + hexs + '}'
        b = bytes.fromhex(hexs.replace('..', '00'))
        out = []
        for off, k, size, name in st[1]:
            raw = b[off:off + size]
            if k in 'hps' and size == 4:
                v = int.from_bytes(raw, 'little')
                if k == 'h':
                    out.append(self.handle(v, create=from_os))
                else:
                    out.append(self.ptr(v, esp, cbentry, from_os))
            elif k in 'cu':
                out.append(hexs[2 * off:2 * (off + size)])
            else:
                out.append(raw.hex())
        return '{' + ','.join(out) + '}'

    def content(self, kind, tok, esp, cbentry, create, sname=None, from_os=False):
        """tok = 'ptr=content' or a bare value; from_os: the content was produced by the OS"""
        if '=' not in tok:
            if tok == '0' or tok.startswith('#'):
                return tok
            try:
                return self.ptr(int(tok, 16), esp, cbentry, from_os and cbentry)
            except ValueError:
                return tok
        p, c = tok.split('=', 1)
        cp = self.ptr(int(p, 16), esp, cbentry, from_os and cbentry)
        b = kind.base
        if b in ('dh', 'I'):
            try:
                c = self.handle(int(c, 16), create=True)
            except ValueError:
                pass
        elif b == 'dp':
            try:
                c = self.ptr(int(c, 16), esp, cbentry, from_os)
            except ValueError:
                pass
        elif b == 'da' and ':' in c:
            v, n = c.split(':')
            v = int(v, 16)
            c = self.region(v, int(n), 'D') + f':{n}' if create else self.ptr(v)
        elif sname and c.startswith('{'):
            m = re.match(r'\{([0-9a-f.]*)\}(.*)$', c)
            if m:
                c = self.hexstruct(sname, m.group(1), esp, cbentry, from_os) + m.group(2)
                c = re.sub(r'(,|^)([0-9a-f]+)=', lambda mm: mm.group(1) + self.ptr(int(mm.group(2), 16), esp, cbentry, from_os) + '=', c)
        return f'{cp}={c}'

    def arg(self, kind, tok, msg=None, wparam=None, esp=None, cbentry=False, phase=0):
        b = kind.base
        # who produced the value: the OS for returns/out-params (C/R) and callback arguments (B)
        from_os = (phase == 1) != cbentry
        if phase == 0 and kind.dir == 'out':
            return self.content(Kind('p'), tok, esp, cbentry, False)
        if b == 'x' or b == 'cb':
            return tok
        if b == 'h':
            try:
                return self.handle(int(tok, 16), create=from_os)
            except ValueError:
                return tok
        if b == 'p':
            try:
                return self.ptr(int(tok, 16), esp, cbentry, from_os)
            except ValueError:
                return tok
        if b == 'S':
            return self.content(kind, tok, esp, cbentry, phase == 1, kind.sub, from_os)
        if b == 'msgl':
            m = self.s.msg.get(msg)
            if m and m[1] not in ('s',):
                sn = m[1] if m[1] != 'NCCALC' else ('NCCALCSIZE_PARAMS' if wparam not in ('0', 0) else 'RECT')
                return self.content(kind, tok, esp, cbentry, False, sn, from_os)
            if m:
                return self.content(kind, tok, esp, cbentry, False, None, from_os)
            return tok          # an integer lParam
        return self.content(kind, tok, esp, cbentry, phase == 1, None, from_os)

    def msg_handles(self, msg, raw, out, wi, create):
        """wParam at raw[wi], lParam at raw[wi+1]: handles for the messages that carry them"""
        for j, is_h in enumerate(MSG_HANDLES.get(msg, (0, 0))):
            if is_h and wi + j < len(raw):
                try:
                    out[wi + j] = self.handle(int(raw[wi + j], 16), create=create)
                except ValueError:
                    pass

    # -- records
    def record(self, r):
        """canonical string of a record, or None to skip"""
        s = self.s
        if r.t == 'B':
            if r.name == 'entry':
                self.stack_top = r.esp
                return 'B entry ' + ' '.join(r.args[:7]) + ' ' + ' '.join(r.args[8:])   # eflags excluded
            self.cb_depth += 1
            self.open.append(r)
            sig = s.get(r.name, True)
            args = list(r.args)
            if sig:
                msg = int(args[1], 16) if r.name in ('wndproc', 'dlgproc') and len(args) > 1 else None
                args = [self.arg(k, t, msg, args[2] if len(args) > 2 else None, r.esp, True) for k, t in zip(sig[2], r.args)]
                if msg is not None:
                    self.msg_handles(msg, r.args, args, 2, True)
            return f'B {r.frame:x} {r.tick:x} {r.depth:x} {r.name} {r.target:x} ' + ' '.join(args)
        if r.t == 'E':
            o = self.open.pop() if self.open else None
            self.cb_depth = max(0, self.cb_depth - 1)
            sig = s.get(r.name, True)
            outs = list(r.outs)
            if sig and o is not None:
                ok = [(i, k) for i, k in enumerate(sig[2]) if k.dir != 'in' or k.base == 'msgl']
                msg = int(o.args[1], 16) if r.name in ('wndproc', 'dlgproc') else None
                if msg is not None:
                    ok = [(i, k) for i, k in ok if k.base != 'msgl' or (s.msg.get(msg, ('in',))[0] == 'io')]
                outs = [self.arg(k, t, msg, o.args[2], o.esp, True, 1) for (i, k), t in zip(ok, r.outs)]
            return f'E {r.depth:x} {r.name} {r.rv} ' + ' '.join(outs)
        sig = s.get(r.name)
        if r.t == 'C':
            if self.stack_top is None:
                self.stack_top = r.esp
            self.open.append(r)
            esp = f'{r.esp - self.stack_top:x}' if (self.cb_depth == 0 and self.stack_top is not None) else '*'
            args = list(r.args)
            if sig:
                args = [self.arg(k, t, esp=r.esp) for k, t in zip(sig[2], r.args)]
                if r.name in MSG_CALLS:
                    i = MSG_CALLS[r.name]
                    try:
                        self.msg_handles(int(r.args[i], 16), r.args, args, i + 1, False)
                    except (ValueError, IndexError):
                        pass
            return f'C {r.frame:x} {r.tick:x} {r.depth:x} {r.ret:x} {esp} {r.name} ' + ' '.join(args)
        # R
        c = self.open.pop() if self.open and self.open[-1].t == 'C' else None
        rv = r.rv
        if sig:
            rk = sig[1]
            if r.name == 'GetProcAddress' and c is not None and rv != '0':
                nm = c.args[1].split('=', 1)[-1].strip('"') if '=' in c.args[1] else c.args[1]
                self.procs[int(rv, 16)] = f'proc({nm})'
                rv = self.procs[int(rv, 16)]
            elif rk.base == 'h':
                rv = self.handle(int(rv, 16), create=True)
            elif rk.base == 'a':
                v, n = rv.split(':')
                rv = (self.region(int(v, 16), int(n)) + ':' + n) if int(v, 16) else '0:' + n
            elif rk.base == 'p':
                rv = self.ptr(int(rv, 16), from_os=True)
            elif rk.base == 's' and '=' in rv:
                p_, c_ = rv.split('=', 1)
                rv = self.ptr(int(p_, 16), from_os=True) + '=' + c_
            elif rk.base in ('eas', 'ews') and '=' in rv:
                p_, c_ = rv.split('=', 1)
                rv = self.ptr(int(p_, 16), from_os=True) + '=' + c_
            ok = [k for k in sig[2] if k.dir != 'in']
            esp = c.esp if c is not None else None
            outs = [self.arg(k, t, esp=esp, phase=1) for k, t in zip(ok, r.outs)]
            if c is not None:
                if r.name in CLOSERS and len(c.args) > CLOSERS[r.name]:
                    try:
                        self.h.pop(int(c.args[CLOSERS[r.name]], 16), None)
                    except ValueError:
                        pass
                if r.name in FREERS and len(c.args) > FREERS[r.name]:
                    try:
                        v = int(c.args[FREERS[r.name]].split('=')[0], 16)
                        self.regions = [x for x in self.regions if x[0] != v]
                    except ValueError:
                        pass
        else:
            outs = r.outs
        return f'R {r.depth:x} {r.name} {rv} ' + ' '.join(outs)


# ------------------------------------------------------------------ commands


def canon_stream(path, sigs, raw=False, ignore=()):
    cz = Canon(sigs)
    skip_depth = None
    for r in records(path):
        if ignore:
            if skip_depth is not None:
                if r.t == 'R' and r.depth == skip_depth:
                    skip_depth = None
                if raw:
                    continue
                cz.record(r)       # keep canonical state (handles, regions) in step
                continue
            if r.t == 'C' and r.name in ignore:
                skip_depth = r.depth
                if not raw:
                    cz.record(r)
                continue
        yield r, (r.line if raw else cz.record(r))


def cmd_diff(a, b, raw=False, ignore=(), context=6):
    sigs = Sigs()
    ga, gb = canon_stream(a, sigs, raw, ignore), canon_stream(b, sigs, raw, ignore)
    hist = []
    n = 0
    stack = []
    while True:
        ra = next(ga, None)
        rb = next(gb, None)
        if ra is None and rb is None:
            print(f'IDENTICAL: {n} records compared' + (' (raw)' if raw else ' (canonical)'))
            return 0
        if ra is None or rb is None or ra[1] != rb[1]:
            print(f'FIRST DIVERGENCE at record {n} (A line {ra[0].no if ra else "-"}, B line {rb[0].no if rb else "-"})')
            if stack:
                print('  open calls (A):')
                for s in stack:
                    print(f'    {s}')
            print('  context:')
            for h in hist[-context:]:
                print(f'    {h}')
            print(f'  A: {ra[1] if ra else "<end of trace>"}')
            print(f'  B: {rb[1] if rb else "<end of trace>"}')
            if ra and rb and not raw:
                print(f'  A raw: {ra[0].line[:400]}')
                print(f'  B raw: {rb[0].line[:400]}')
            return 1
        r = ra[0]
        if r.t in ('C', 'B'):
            stack.append(ra[1][:160])
        elif r.t in ('R', 'E') and stack:
            stack.pop()
        hist.append(ra[1][:300])
        if len(hist) > 64:
            del hist[:32]
        n += 1


def decode_struct(sigs, sname, hexs):
    st = sigs.struct.get(sname)
    if not st or len(hexs) != 2 * st[0]:
        return '{' + hexs + '}'
    b = bytes.fromhex(hexs.replace('..', '00'))
    out = []
    for off, k, size, name in st[1]:
        raw = b[off:off + size]
        if k == 'c':
            s = raw.split(b'\0', 1)[0].decode('latin-1')
            out.append(f'{name}={s!r}')
        elif k == 'b':
            out.append(f'{name}={raw.hex()}')
        elif k == 'u':
            continue
        else:
            v = int.from_bytes(raw, 'little')
            out.append(f'{name}={v:#x}' if v > 9 else f'{name}={v}')
    return '{' + ' '.join(out) + '}'


def pretty_tok(sigs, kind, tok, msg=None, wparam=None):
    if kind is None or '=' not in tok:
        return tok
    p, c = tok.split('=', 1)
    sname = None
    if kind.base == 'S':
        sname = kind.sub
    elif kind.base == 'msgl' and msg in sigs.msg and sigs.msg[msg][1] != 's':
        sname = sigs.msg[msg][1]
        if sname == 'NCCALC':
            sname = 'NCCALCSIZE_PARAMS' if wparam not in ('0', None) else 'RECT'
    if sname:
        m = re.match(r"\{([0-9a-f.]*)\}(.*)$", c)
        if m:
            c = decode_struct(sigs, sname, m.group(1)) + m.group(2)
    return f'{p}={c}'


def cmd_dump(path, canon=False, start=0, count=None, grep=None):
    sigs = Sigs()
    cz = Canon(sigs) if canon else None
    pend = None    # a C record waiting for its R
    rx = re.compile(grep) if grep else None
    shown = 0
    opened = []

    def emit(s):
        nonlocal shown
        if rx and not rx.search(s):
            return
        if shown >= start and (count is None or shown < start + count):
            print(s)
        shown += 1

    def fmt_call(c, ctext):
        sig = sigs.get(c.name)
        if canon:
            return ctext
        args = c.args
        if sig:
            args = [pretty_tok(sigs, k, t) for k, t in zip(sig[2], c.args)]
        return f'{c.name}({", ".join(args)})'

    for r in records(path):
        ctext = cz.record(r) if cz else None
        ind = '  ' * r.depth
        if r.t == 'C':
            if pend:
                emit(f'[{pend[0].frame}/{pend[0].tick}] {"  " * pend[0].depth}{pend[0].ret:06x}: {fmt_call(*pend)} ...')
            pend = (r, ctext)
            opened.append(r)
            continue
        if r.t == 'R':
            c = opened.pop() if opened else None
            sig = sigs.get(r.name)
            outs = r.outs
            if sig and not canon:
                ok = [k for k in sig[2] if k.dir != 'in']
                outs = [pretty_tok(sigs, k, t) for k, t in zip(ok, r.outs)]
            tail = f'-> {ctext if canon else r.rv}' + ('' if canon else (' ' + ' '.join(outs) if outs else ''))
            if pend and c is pend[0]:
                emit(f'[{c.frame}/{c.tick}] {ind}{c.ret:06x}: {fmt_call(*pend)} {tail}')
            else:
                if pend:
                    emit(f'[{pend[0].frame}/{pend[0].tick}] {"  " * pend[0].depth}{pend[0].ret:06x}: {fmt_call(*pend)} ...')
                emit(f'        {ind}... {r.name} {tail}')
            pend = None
            continue
        if pend:
            emit(f'[{pend[0].frame}/{pend[0].tick}] {"  " * pend[0].depth}{pend[0].ret:06x}: {fmt_call(*pend)} ...')
            pend = None
        if r.t == 'B':
            sig = sigs.get(r.name, True)
            args = r.args
            if sig and not canon:
                msg = int(r.args[1], 16) if r.name in ('wndproc', 'dlgproc') else None
                args = [pretty_tok(sigs, k, t, msg, r.args[2] if len(r.args) > 2 else None) for k, t in zip(sig[2], r.args)]
            emit(f'[{r.frame}/{r.tick}] {ind}>> {r.name} {r.target:x}' + (f' ({", ".join(args)})' if not canon else ' ' + ctext))
        elif r.t == 'E':
            emit(f'        {ind}<< {r.name} -> {ctext if canon else r.rv + (" " + " ".join(r.outs) if r.outs else "")}')
    if pend:
        emit(f'[{pend[0].frame}/{pend[0].tick}] {"  " * pend[0].depth}{pend[0].ret:06x}: {fmt_call(*pend)} ...')


def strip_cr(text):
    """drop frame/tick/depth/esp fields: the shape of a call"""
    p = text.split(' ')
    if p[0] == 'C':
        return p[4], ' '.join(p[6:])      # call site, name+args
    if p[0] == 'B':
        return p[5], ' '.join(p[4:5] + p[6:])
    return None, ' '.join(p[2:])


def cmd_shapes(paths, canon=False, top=8, name_rx=None):
    sigs = Sigs()
    shapes = defaultdict(Counter)
    calls = Counter()
    sites = defaultdict(set)
    rx = re.compile(name_rx) if name_rx else None
    for path in paths:
        cz = Canon(sigs)
        opened = []
        for r in records(path):
            text = cz.record(r) if canon else r.line
            if r.t in ('C', 'B'):
                opened.append((r, text))
            elif r.t in ('R', 'E') and opened:
                c, ctext = opened.pop()
                site, call = strip_cr(ctext)
                _, res = strip_cr(text)
                key = c.name if c.t == 'C' else 'callback:' + c.name
                if rx and not rx.search(key):
                    continue
                calls[key] += 1
                sites[key].add(site)
                shapes[key][call + '  ->  ' + res] += 1
    for key in sorted(calls, key=lambda k: (-calls[k], k)):
        print(f'{calls[key]:9d}  {key}   ({len(shapes[key])} shapes, {len(sites[key])} call sites)')
        for sh, n in shapes[key].most_common(top):
            print(f'           {n:8d}  {sh[:400]}')
        if len(shapes[key]) > top:
            print(f'           ... {len(shapes[key]) - top} more shapes')


def cmd_check(path):
    sigs = Sigs()
    stack, n, errs = [], 0, 0
    names = Counter()
    for r in records(path):
        n += 1
        if r.t == 'B' and r.name == 'entry':
            continue
        if r.t in ('C', 'B'):
            if r.depth != len(stack):
                print(f'line {r.no}: depth {r.depth}, expected {len(stack)}')
                errs += 1
            if r.t == 'C' and r.name not in sigs.fn:
                names[r.name] += 1
            stack.append(r)
        else:
            if not stack or stack[-1].name != r.name or (r.t == 'R') != (stack[-1].t == 'C'):
                print(f'line {r.no}: {r.t} {r.name} does not close {stack[-1].t + " " + stack[-1].name if stack else "nothing"}')
                errs += 1
            else:
                stack.pop()
    for nm, c in names.items():
        print(f'no signature: {nm} ({c} calls)')
    print(f'{n} records, {errs} nesting errors, {len(names)} names without signature, {len(stack)} open at end')
    return 1 if errs or names else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    d = sub.add_parser('dump')
    d.add_argument('trace')
    d.add_argument('--canon', action='store_true')
    d.add_argument('--from', dest='start', type=int, default=0)
    d.add_argument('--count', type=int)
    d.add_argument('--grep')
    f = sub.add_parser('diff')
    f.add_argument('a')
    f.add_argument('b')
    f.add_argument('--raw', action='store_true')
    f.add_argument('--ignore', default='')
    f.add_argument('--context', type=int, default=6)
    s = sub.add_parser('shapes')
    s.add_argument('traces', nargs='+')
    s.add_argument('--canon', action='store_true')
    s.add_argument('--top', type=int, default=8)
    s.add_argument('--name')
    c = sub.add_parser('check')
    c.add_argument('trace')
    a = ap.parse_args(argv[1:])
    try:
        if a.cmd == 'dump':
            cmd_dump(a.trace, a.canon, a.start, a.count, a.grep)
            return 0
        if a.cmd == 'diff':
            return cmd_diff(a.a, a.b, a.raw, set(x for x in a.ignore.split(',') if x), a.context)
        if a.cmd == 'shapes':
            cmd_shapes(a.traces, a.canon, a.top, a.name)
            return 0
        if a.cmd == 'check':
            return cmd_check(a.trace)
    except BrokenPipeError:
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
