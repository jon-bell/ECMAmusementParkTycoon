#!/usr/bin/env python3
"""CPU differential tests: the lifted instruction semantics vs the host CPU (via Wine).

  .venv/bin/python lift/test/cpu/cpudiff.py gen  --set map|synth [--per N] [--seed S] [--limit N] --out DIR
  .venv/bin/python lift/test/cpu/cpudiff.py run  --dir DIR [--jobs J]
  (then)  /usr/bin/nodejs lift/test/cpu/compare.js DIR <single-lift-dir>

`gen` writes DIR/tests.bin (+ forms.json, image.bin). `--set map`: every instruction start of the
code map (out/spikes/s1v4/cfg.json), executed at its own address from the user's rct.exe image.
`--set synth`: hand-encoded instructions (all shift/rotate counts, every ALU form at 8/16/32 bit,
mul/div/bt/bsf/setcc/jcc/string forms) placed at 0x02800000+; DIR/synth.json lists their bytes
for `lifter.py --insns`.

`run` executes DIR/tests.bin natively with harness.exe under 32-bit Wine (parallel chunks; a
crash or hang of the native side is recorded as such and the chunk resumes after it) and
writes DIR/results.bin.

Everything written derives from the user's binary and stays under out/ (git-ignored).
"""
import argparse
import json
import os
import random
import struct
import subprocess
import sys
import time

import capstone
from capstone import x86 as X
import pefile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
IB = 0x400000
IMG_HI = 0x9C4000
HOST_BASE = 0xFFF00000
SCR, SCR_HI = 0x02000000, 0x02100000
STK, STK_HI = 0x02100000, 0x02400000
SYN = 0x02800000
RO_SPANS = [(0x400000, 0x5E9000), (0x9B3000, 0x9C4000)]     # read-only to the guest
RW_SPANS = [(0x5E9000, 0x9B3000), (SCR, SCR_HI), (STK, STK_HI)]

SPECIAL = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000,
           0xFFFFFFFF, 0xFFFFFF80, 0xFFFF8000, 0x8080, 0x80808080, 0x0F, 0x10, 0xFFFFFFFE]
R32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
R16 = {'ax': 'eax', 'cx': 'ecx', 'dx': 'edx', 'bx': 'ebx', 'sp': 'esp', 'bp': 'ebp', 'si': 'esi', 'di': 'edi'}
R8 = {'al': 'eax', 'cl': 'ecx', 'dl': 'edx', 'bl': 'ebx', 'ah': 'eax', 'ch': 'ecx', 'dh': 'edx', 'bh': 'ebx'}
STACK_OPS = {'push', 'pop', 'call', 'ret', 'pushal', 'popal', 'pushf', 'popf', 'pushfd', 'popfd', 'leave'}
SKIP = {'int3', 'cpuid', 'fld', 'fstp', 'fmul', 'fdiv', 'fsubr', 'fcomp', 'fnstsw', 'fnstcw', 'fldcw', 'fnclex', 'wait'}


def full(r):
    return r if r in R32 else R16.get(r) or R8.get(r)


def rnd(rng):
    x = rng.random()
    if x < 0.3:
        return rng.choice(SPECIAL)
    if x < 0.45:
        return rng.randrange(0, 257)
    return rng.getrandbits(32)


def stack_val(rng):
    return 0x02300000 + rng.randrange(0, 0x80000) * 4 // 4 & ~3


def build_image(exe):
    pe = pefile.PE(exe)
    img = bytearray(pe.get_memory_mapped_image())
    img = img[:IMG_HI - IB] + bytes(max(0, IMG_HI - IB - len(img)))
    k = 0
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        for i in e.imports:
            struct.pack_into('<I', img, i.address - IB, (HOST_BASE + 16 * k) & 0xFFFFFFFF)
            k += 1
    return bytes(img)


def prot_spans(lo, hi):
    """Split [lo, hi) into (lo, hi, ro) pieces inside mapped memory."""
    out = []
    for spans, ro in ((RO_SPANS, 1), (RW_SPANS, 0)):
        for a, b in spans:
            x, y = max(lo, a), min(hi, b)
            if x < y:
                out.append((x, y, ro))
    return sorted(out)


class Gen:
    def __init__(self, image, seed):
        self.img = image
        self.rng = random.Random(seed)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True

    def tests_for(self, i, n, code=None):
        out = []
        for _ in range(n):
            t = self.one(i, code)
            if t:
                out.append(t)
        return out

    def one(self, i, code):
        rng = self.rng
        mn = i.mnemonic
        base = mn.split()[-1]
        regs = {r: rnd(rng) for r in R32}
        regs['esp'] = stack_val(rng)
        fl = 0
        for b in (0, 2, 4, 6, 7, 11):
            if rng.random() < 0.5:
                fl |= 1 << b
        regions = []          # (lo, hi)
        fixups = []           # (addr, dword) written into region content after randomisation
        writes_esp = any(i.reg_name(r) == 'esp' for r in i.regs_access()[1]) and mn not in STACK_OPS
        is_string = base in ('movsb', 'movsw', 'movsd', 'stosb', 'stosw', 'stosd', 'scasb')
        flags = 0
        if is_string:
            if rng.random() < 0.5:
                fl |= 1 << 10
            n = {'b': 1, 'w': 2, 'd': 4}[base[-1]]
            rep = i.prefix[0] in (0xF2, 0xF3)
            if rep:
                flags |= 1
                regs['ecx'] = rng.choice([0, 1, 2, 3, rng.randrange(0, 48)])
            cnt = regs['ecx'] if rep else 1
            span = n * cnt + 16
            regs['edi'] = SCR + 0x40000 + rng.randrange(0, 0x40000)
            if base.startswith('movs'):
                if rng.random() < 0.3:
                    regs['esi'] = (regs['edi'] + rng.randrange(-24, 25)) & 0xFFFFFFFF
                else:
                    regs['esi'] = SCR + 0x90000 + rng.randrange(0, 0x40000)
                regions.append((regs['esi'] - span, regs['esi'] + span))
            regions.append((regs['edi'] - span, regs['edi'] + span))
        # explicit memory operands
        lea = mn == 'lea'
        for o in i.operands:
            if o.type != X.X86_OP_MEM:
                continue
            mm = o.mem
            if mm.segment and i.reg_name(mm.segment) == 'fs':
                return None
            b = i.reg_name(mm.base) if mm.base else None
            x = i.reg_name(mm.index) if mm.index else None
            sc = mm.scale
            disp = mm.disp & 0xFFFFFFFF
            sdisp = disp - (1 << 32) if disp & 0x80000000 else disp
            want_stack = lea and writes_esp
            if b == 'esp':
                if x:
                    regs[x] = rng.randrange(0, 64)
            elif b is None and x is None:
                pass
            elif IB <= disp < IMG_HI and not want_stack:
                # array/table at a fixed address indexed by small registers
                if x:
                    regs[x] = rng.randrange(0, 64)
                if b:
                    regs[b] = rng.randrange(0, 0x400)
                    if x == b:
                        regs[x] = rng.randrange(0, 64)
            else:
                T = stack_val(rng) if want_stack else SCR + rng.randrange(0x1000, 0x3F000)
                if b and x and b != x:
                    regs[x] = rng.randrange(0, 0x400)
                    regs[b] = (T - sdisp - regs[x] * sc) & 0xFFFFFFFF
                elif b and x:
                    v = (T - sdisp) // (1 + sc)
                    regs[b] = v & 0xFFFFFFFF
                elif b:
                    regs[b] = (T - sdisp) & 0xFFFFFFFF
                else:
                    regs[x] = ((T - sdisp) // sc) & 0xFFFFFFFF
            if lea:
                continue
            ea = (regs[b] if b else 0) + (regs[x] * sc if x else 0) + sdisp
            if mn == 'pop' and b == 'esp':
                ea += o.size
            ea &= 0xFFFFFFFF
            regions.append((ea - 16, ea + o.size + 16))
            if mn in ('bt', 'bts', 'btr', 'btc') and i.operands[1].type == X.X86_OP_REG:
                r = full(i.reg_name(i.operands[1].reg))
                if r not in (b, x, 'esp'):
                    off = rng.randrange(-300, 300)
                    regs[r] = off & (0xFFFF if o.size == 2 else 0xFFFFFFFF) | (regs[r] & 0xFFFF0000 if o.size == 2 else 0)
                regions.append((ea - 48, ea + 48))
            if writes_esp and mn in ('mov', 'xchg') and o is i.operands[-1]:
                fixups.append((ea, stack_val(rng)))
        # stack
        if mn in STACK_OPS or any(i.reg_name(r) == 'esp' for r in i.regs_access()[0]):
            extra = 64
            if mn == 'ret' and i.operands:
                extra += i.operands[0].imm
            regions.append((regs['esp'] - 64, regs['esp'] + extra))
        if mn == 'leave':
            regs['ebp'] = stack_val(rng)
            regions.append((regs['ebp'] - 16, regs['ebp'] + 16))
        if mn == 'pop' and i.operands[0].type == X.X86_OP_REG and i.reg_name(i.operands[0].reg) == 'esp':
            fixups.append((regs['esp'], stack_val(rng)))
        if writes_esp and mn in ('mov', 'xchg'):
            for o in i.operands:
                if o.type == X.X86_OP_REG and i.reg_name(o.reg) != 'esp':
                    regs[full(i.reg_name(o.reg))] = stack_val(rng)
        elif writes_esp and mn not in ('lea',):
            for o in i.operands:
                if o.type == X.X86_OP_REG and i.reg_name(o.reg) != 'esp':
                    regs[full(i.reg_name(o.reg))] = rng.randrange(0, 0x1000)
        # shifts by cl, divisions
        if base in ('shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'shrd', 'shld') and \
                i.operands[-1].type == X.X86_OP_REG and i.reg_name(i.operands[-1].reg) == 'cl':
            c = rng.choice([0, 1, 2, rng.randrange(0, 34), rng.randrange(0, 256)])
            regs['ecx'] = (regs['ecx'] & 0xFFFFFF00) | c
        if mn in ('div', 'idiv'):
            self.fix_div(i, regs)
        # region content
        recs = []
        for lo, hi in merge(regions):
            for a, b_, ro in prot_spans(lo, hi):
                if ro:
                    data = self.img[a - IB:b_ - IB]
                else:
                    data = bytearray(rng.getrandbits(8) for _ in range(b_ - a))
                    if base == 'scasb' and rng.random() < 0.5:
                        al = regs['eax'] & 0xFF
                        for k in range(len(data)):
                            if rng.random() < 0.1:
                                data[k] = al
                    for fa, fv in fixups:
                        for k in range(4):
                            if a <= fa + k < b_:
                                data[fa + k - a] = (fv >> (8 * k)) & 0xFF
                recs.append((a, bytes(data), ro))
        return (i.address, flags, [regs[r] & 0xFFFFFFFF for r in R32], fl, code or b'', recs)

    def fix_div(self, i, regs):
        rng = self.rng
        o = i.operands[0]
        w = o.size * 8
        if o.type == X.X86_OP_REG:
            r = full(i.reg_name(o.reg))
            hi8 = i.reg_name(o.reg) in ('ah', 'bh', 'ch', 'dh')
            v = rng.choice([1, 2, 3, 7, 10, rng.randrange(1, 1 << w), (1 << w) - 1, 1 << (w - 1)])
            if hi8:
                regs[r] = (regs[r] & ~0xFF00 | v << 8) & 0xFFFFFFFF
            else:
                regs[r] = (regs[r] & ~((1 << w) - 1) | v) & 0xFFFFFFFF if w < 32 else v
        if rng.random() < 0.7:
            if i.mnemonic == 'div':
                if w == 8:
                    regs['eax'] &= 0xFFFF00FF
                elif w == 16:
                    regs['edx'] &= 0xFFFF0000
                else:
                    regs['edx'] = rng.randrange(0, 4)
            else:
                if w == 8:
                    regs['eax'] = regs['eax'] & 0xFFFF00FF | (0xFF00 if regs['eax'] & 0x80 else 0)
                elif w == 16:
                    regs['edx'] = regs['edx'] & 0xFFFF0000 | (0xFFFF if regs['eax'] & 0x8000 else 0)
                else:
                    regs['edx'] = 0xFFFFFFFF if regs['eax'] & 0x80000000 else 0


def merge(regs):
    out = []
    for lo, hi in sorted((max(0, a), b) for a, b in regs):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def pack_test(t):
    addr, flags, regs, fl, code, recs = t
    b = bytearray(struct.pack('<II', addr, flags))
    b += struct.pack('<8I', *regs) + struct.pack('<I', fl)
    b += struct.pack('<I', len(code)) + code + bytes((-len(code)) % 4)
    b += struct.pack('<I', len(recs))
    for a, data, ro in recs:
        b += struct.pack('<III', a, len(data), ro) + data + bytes((-len(data)) % 4)
    return bytes(b)


# ------------------------------- synthetic instructions -------------------------------
def synth_insns():
    """(bytes, note) of hand-encoded instructions covering forms and counts beyond the map."""
    out = []
    MODRM = lambda reg, rm: 0xC0 | (reg << 3) | rm
    # ALU reg,reg and reg,imm at 8/16/32 (incl. high bytes)
    pairs8 = [(0, 1), (4, 3), (6, 5), (3, 3), (0, 4)]       # al,cl ah,bl dh,ch bl,bl al,ah (rm,reg)
    for op in range(8):
        for rm, reg in pairs8:
            out.append(bytes([op * 8 + 0, MODRM(reg, rm)]))
        for pfx in (b'', b'\x66'):
            for rm, reg in [(0, 1), (3, 6), (2, 2)]:
                out.append(pfx + bytes([op * 8 + 1, MODRM(reg, rm)]))
            out.append(pfx + bytes([0x83, MODRM(op, 1), 0x80]))
            out.append(pfx + bytes([0x83, MODRM(op, 2), 0x7F]))
            out.append(pfx + bytes([0x81, MODRM(op, 3)]) + (b'\x34\x12' if pfx else b'\x78\x56\x34\x12'))
        out.append(bytes([0x80, MODRM(op, 4), 0x9C]))         # op ah, imm8
        out.append(bytes([0x80, MODRM(op, 0), 0x01]))
    # test
    out += [bytes([0x84, MODRM(1, 0)]), bytes([0x84, MODRM(7, 4)]), bytes([0x85, MODRM(1, 0)]), b'\x66\x85\xc8',
            bytes([0xF6, MODRM(0, 4), 0x81]), b'\xa9\x01\x00\x00\x80']
    # inc dec neg not (8/16/32, high byte)
    for r in (0, 4, 7):
        out += [bytes([0xFE, MODRM(0, r)]), bytes([0xFE, MODRM(1, r)])]
    for pfx in (b'', b'\x66'):
        for r in (0, 3):
            out += [pfx + bytes([0x40 + r]), pfx + bytes([0x48 + r]), pfx + bytes([0xF7, MODRM(3, r)]),
                    pfx + bytes([0xF7, MODRM(2, r)])]
    out += [bytes([0xF6, MODRM(3, 0)]), bytes([0xF6, MODRM(3, 4)]), bytes([0xF6, MODRM(2, 7)])]
    # shifts/rotates: every op, width, count 0..33 immediate, by-1, by-cl
    for n in (0, 1, 2, 3, 4, 5, 7):
        for pfx, opc_i, opc_1, opc_cl, rms in ((b'', 0xC0, 0xD0, 0xD2, (0, 4)), (b'\x66', 0xC1, 0xD1, 0xD3, (0,)),
                                               (b'', 0xC1, 0xD1, 0xD3, (0,))):
            for rm in rms:
                for c in list(range(0, 34)) + [0x41, 0xFF]:
                    out.append(pfx + bytes([opc_i, MODRM(n, rm), c]))
                out.append(pfx + bytes([opc_1, MODRM(n, rm)]))
                out.append(pfx + bytes([opc_cl, MODRM(n, rm)]))
    # shrd/shld r32, imm and cl
    for c in list(range(0, 33)):
        out.append(bytes([0x0F, 0xAC, MODRM(1, 0), c]))
    out.append(b'\x0f\xad\xd0')
    # mul/imul/div/idiv: 8 (al, ah src), 16, 32
    for n in (4, 5, 6, 7):
        out += [bytes([0xF6, MODRM(n, 3)]), bytes([0xF6, MODRM(n, 7)]), b'\x66' + bytes([0xF7, MODRM(n, 3)]),
                bytes([0xF7, MODRM(n, 3)])]
    out += [b'\x0f\xaf\xc3', b'\x66\x0f\xaf\xc3', b'\x6b\xc3\x85', b'\x66\x6b\xc3\x85', b'\x69\xc3\x01\x00\x01\x80',
            b'\x66\x69\xc3\x34\x82']
    # bt family: reg,reg ; reg,imm (16/32) ; mem forms come from the map
    for n, opc in ((4, 0xA3), (5, 0xAB), (6, 0xB3), (7, 0xBB)):
        out += [bytes([0x0F, opc, MODRM(1, 0)]), b'\x66' + bytes([0x0F, opc, MODRM(1, 0)])]
        for c in (0, 5, 15, 16, 31, 37):
            out += [bytes([0x0F, 0xBA, MODRM(n, 0), c]), b'\x66' + bytes([0x0F, 0xBA, MODRM(n, 0), c])]
    # bsf
    out += [b'\x0f\xbc\xc3', b'\x66\x0f\xbc\xc3']
    # setcc / jcc (all 16 conditions)
    for cc in range(16):
        out.append(bytes([0x0F, 0x90 + cc, MODRM(0, 0)]))
        out.append(bytes([0x70 + cc, 0x10]))
    # loop / jcxz family (with and without 0x67)
    out += [b'\xe2\x10', b'\x67\xe2\x10', b'\xe3\x10', b'\x67\xe3\x10']
    # string ops with DF and overlap
    out += [b'\xf3\xa4', b'\xf3\x66\xa5', b'\xf3\xa5', b'\xa4', b'\x66\xa5', b'\xa5', b'\xf3\xaa', b'\xf3\x66\xab',
            b'\xf3\xab', b'\xaa', b'\x66\xab', b'\xab', b'\xf2\xae', b'\xae']
    # flags and misc
    out += [b'\xf9', b'\xf8', b'\xfd', b'\xfc', b'\x66\x9c', b'\x66\x9d', b'\x99', b'\x60', b'\x61', b'\xc9',
            b'\x86\xc4', b'\x66\x0f\xbe\xc4', b'\x0f\xbf\xc3', b'\x0f\xb6\xc4']
    return out


def cmd_gen(a):
    os.makedirs(a.out, exist_ok=True)
    exe = os.path.join(ROOT, 'game/cd/English/rct.exe')
    image = build_image(exe)
    with open(os.path.join(a.out, 'image.bin'), 'wb') as f:
        f.write(image)
    g = Gen(image, a.seed)
    tests = []
    forms = {}
    if a.set == 'map':
        cfg = json.load(open(os.path.join(ROOT, 'out/spikes/s1v4/cfg.json')))
        addrs = cfg['instruction_starts']
        if a.limit:
            random.Random(a.seed).shuffle(addrs)
            addrs = sorted(addrs[:a.limit])
        for ad in addrs:
            i = next(g.md.disasm(image[ad - IB:ad - IB + 16], ad, 1))
            if i.mnemonic in SKIP:
                continue
            forms[ad] = form_key(i)
            tests += g.tests_for(i, a.per)
    else:
        syn = []
        for k, code in enumerate(synth_insns()):
            ad = SYN + 16 * k
            i = next(g.md.disasm(code + b'\x90' * 8, ad, 1), None)
            if i is None or i.size != len(code):
                raise SystemExit(f'bad synthetic encoding {code.hex()}')
            syn.append({'addr': ad, 'hex': code.hex()})
            forms[ad] = form_key(i)
            tests += g.tests_for(i, a.per, code)
        with open(os.path.join(a.out, 'synth.json'), 'w') as f:
            json.dump(syn, f)
    with open(os.path.join(a.out, 'tests.bin'), 'wb') as f:
        f.write(b'CPT1' + struct.pack('<I', len(tests)))
        for t in tests:
            f.write(pack_test(t))
    with open(os.path.join(a.out, 'forms.json'), 'w') as f:
        json.dump({str(k): v for k, v in forms.items()}, f)
    print(f'{len(tests)} tests for {len(forms)} instructions -> {a.out}')


def form_key(i):
    ops = []
    for o in i.operands:
        if o.type == X.X86_OP_REG:
            n = i.reg_name(o.reg)
            ops.append(('r%d' % (o.size * 8)) + ('h' if n in ('ah', 'bh', 'ch', 'dh') else ''))
        elif o.type == X.X86_OP_IMM:
            ops.append('i')
        else:
            ops.append('m%d' % (o.size * 8))
    pf = 'a16 ' if i.prefix[3] == 0x67 else ''
    return f'{pf}{i.mnemonic} {",".join(ops)}|{i.address:08x}: {i.mnemonic} {i.op_str}'


# ------------------------------------- running -------------------------------------
def read_tests(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'CPT1'
    n = struct.unpack_from('<I', d, 4)[0]
    p = 8
    out = []
    for _ in range(n):
        q = p
        p += 8 + 32 + 4
        nc = struct.unpack_from('<I', d, p)[0]
        p += 4 + ((nc + 3) & ~3)
        nr = struct.unpack_from('<I', d, p)[0]
        p += 4
        rl = 0
        for _ in range(nr):
            ln = struct.unpack_from('<I', d, p + 4)[0]
            p += 12 + ((ln + 3) & ~3)
            rl += (ln + 3) & ~3
        out.append((q, p, 48 + rl))
    return d, out


def cmd_run(a):
    d, recs = read_tests(os.path.join(a.dir, 'tests.bin'))
    n = len(recs)
    J = a.jobs
    per = (n + J - 1) // J
    env = dict(os.environ)
    env.pop('TMPDIR', None)
    env.update(WINEPREFIX=os.path.join(ROOT, 'out/cpu/prefix'), WINEARCH='win32', WINEDEBUG='-all')
    harness = os.path.join(ROOT, 'out/cpu/harness.exe')
    image = os.path.join(a.dir, 'image.bin')
    chunks = []
    for k in range(J):
        lo, hi = k * per, min(n, (k + 1) * per)
        if lo >= hi:
            break
        cd = os.path.join(a.dir, f'chunk{k:02d}')
        os.makedirs(cd, exist_ok=True)
        with open(os.path.join(cd, 'tests.bin'), 'wb') as f:
            f.write(b'CPT1' + struct.pack('<I', hi - lo))
            for q, p, _ in recs[lo:hi]:
                f.write(d[q:p])
        chunks.append((cd, lo, hi))
    t0 = time.time()
    crashes = []

    def done_count(cd, lo, hi):
        rp = os.path.join(cd, 'results.bin')
        if not os.path.exists(rp):
            return 0, 0
        sz = os.path.getsize(rp)
        off, c = 16, 0
        for q, p, rl in recs[lo:hi]:
            if off + rl > sz:
                break
            off += rl
            c += 1
        return c, off

    procs = {}
    state = {cd: 0 for cd, _, _ in chunks}

    def start(cd, lo, hi, first):
        args = ['wine', harness, image, os.path.join(cd, 'tests.bin'), os.path.join(cd, 'results.bin'), str(first)]
        return subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=open(os.path.join(cd, 'err.log'), 'a'))

    for cd, lo, hi in chunks:
        procs[cd] = (start(cd, lo, hi, 0), time.time(), lo, hi)
    while procs:
        time.sleep(0.5)
        for cd in list(procs):
            pr, ts, lo, hi = procs[cd]
            rc = pr.poll()
            c, off = done_count(cd, lo, hi)
            if rc is None and time.time() - ts < a.timeout:
                continue
            if rc is None:
                pr.kill()
                pr.wait()
            if c >= hi - lo:
                del procs[cd]
                continue
            if rc == 2:
                sys.exit(f'harness setup failed in {cd}: ' + open(os.path.join(cd, 'err.log')).read()[-500:])
            # crash or hang at test c: truncate, write a placeholder record, resume after it
            with open(os.path.join(cd, 'results.bin'), 'r+b' if off else 'wb') as f:
                if off == 0:
                    f.write(struct.pack('<4I', 0x31525043, hi - lo, 0, 0))
                    off = 16
                f.truncate(off)
                f.seek(off)
                rl = recs[lo + c][2]
                f.write(struct.pack('<I', 0xFFFFFFFF) + bytes(rl - 4))
            crashes.append(lo + c)
            procs[cd] = (start(cd, lo, hi, c + 1), time.time(), lo, hi)
    # merge
    with open(os.path.join(a.dir, 'results.bin'), 'wb') as f:
        hdr = None
        for cd, lo, hi in chunks:
            r = open(os.path.join(cd, 'results.bin'), 'rb').read()
            if hdr is None:
                hdr = bytearray(r[:16])
                struct.pack_into('<I', hdr, 4, n)
                f.write(hdr)
            f.write(r[16:])
    print(f'{n} tests natively in {time.time() - t0:.1f}s; native crashes/hangs: {len(crashes)} {crashes[:20]}')


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    g = sp.add_parser('gen')
    g.add_argument('--set', choices=('map', 'synth'), default='map')
    g.add_argument('--per', type=int, default=4)
    g.add_argument('--seed', type=int, default=1)
    g.add_argument('--limit', type=int, default=0)
    g.add_argument('--out', required=True)
    r = sp.add_parser('run')
    r.add_argument('--dir', required=True)
    r.add_argument('--jobs', type=int, default=8)
    r.add_argument('--timeout', type=float, default=600)
    a = ap.parse_args()
    {'gen': cmd_gen, 'run': cmd_run}[a.cmd](a)


if __name__ == '__main__':
    main()
