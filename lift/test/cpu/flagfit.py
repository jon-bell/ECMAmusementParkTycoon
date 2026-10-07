#!/usr/bin/env python3
"""Fit the SDM-undefined flags to native results (calibrates HW_MODEL / ops.js HW).

  .venv/bin/python lift/test/cpu/flagfit.py <synthetic test dir>

Uses the register-operand synthetic tests (cpudiff.py gen --set synth). For each group
(mnemonic, width, count class) and each arithmetic flag, reports which candidate rules agree with
the native result on every sample. A rule that fits all samples of a well-populated group is
adopted in lift/lifter.py HW_MODEL and lift/runtime/ops.js HW.
"""
import collections
import struct
import sys

import capstone
from capstone import x86 as X

sys.path.insert(0, __import__('os').path.dirname(__file__))
import cpudiff as C  # noqa: E402

FB = {'c': 0, 'p': 2, 'a': 4, 'z': 6, 's': 7, 'o': 11}
R32 = C.R32
P = [1 - bin(i).count('1') % 2 for i in range(256)]


def regval(name, regs):
    full = C.full(name)
    v = regs[R32.index(full)]
    if name in R32:
        return v, 32
    if name in C.R16:
        return v & 0xFFFF, 16
    if name in ('ah', 'bh', 'ch', 'dh'):
        return (v >> 8) & 0xFF, 8
    return v & 0xFF, 8


def main():
    d, recs = C.read_tests(sys.argv[1] + '/tests.bin')
    R = open(sys.argv[1] + '/results.bin', 'rb').read()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rp = 16
    groups = collections.defaultdict(list)
    cache = {}
    for (q, p, rl) in recs:
        addr, flags = struct.unpack_from('<II', d, q)
        regs = list(struct.unpack_from('<8I', d, q + 8))
        efl = struct.unpack_from('<I', d, q + 40)[0]
        nc = struct.unpack_from('<I', d, q + 44)[0]
        code = d[q + 48:q + 48 + nc]
        res = struct.unpack_from('<12I', R, rp)
        rp += rl
        if res[0] != 0x80000004:
            continue
        out = list(res[2:10])
        eflo = res[11]
        if addr not in cache:
            cache[addr] = next(md.disasm(code + b'\x90' * 8, addr, 1))
        i = cache[addr]
        mn = i.mnemonic
        ops = i.operands
        if not ops or any(o.type == X.X86_OP_MEM for o in ops):
            continue
        if mn in ('shl', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'shrd'):
            dn = i.reg_name(ops[0].reg)
            dv, w = regval(dn, regs)
            rv, _ = regval(dn, out)
            if ops[-1].type == X.X86_OP_IMM:
                c = ops[-1].imm & 31
            elif len(ops) == 1:
                c = 1
            else:
                c = regs[1] & 31
            sv = regval(i.reg_name(ops[1].reg), regs)[0] if mn == 'shrd' else 0
            cls = 'c0' if c == 0 else 'c1' if c == 1 else ('c<=w' if c <= w else 'c>w')
            key = (mn, w, cls)
            groups[key].append(dict(d=dv, s=sv, c=c, r=rv, w=w, fi=efl, fo=eflo))
        elif mn in ('mul', 'imul', 'div', 'idiv') and len(ops) == 1:
            sn = i.reg_name(ops[0].reg)
            sv, w = regval(sn, regs)
            if w == 8:
                lo, hi = out[0] & 0xFF, (out[0] >> 8) & 0xFF
                dlo = regs[0] & 0xFFFF
            elif w == 16:
                lo, hi = out[0] & 0xFFFF, out[2] & 0xFFFF
                dlo = regs[0] & 0xFFFF
            else:
                lo, hi = out[0], out[2]
                dlo = regs[0]
            groups[(mn, w, '')].append(dict(d=dlo, s=sv, r=lo, hi=hi, w=w, fi=efl, fo=eflo, ein=regs[0], edx=regs[2]))
        elif mn == 'imul' and len(ops) >= 2:
            dn = i.reg_name(ops[0].reg)
            rv, w = regval(dn, out)
            groups[('imul2', w, '')].append(dict(d=0, s=0, r=rv, w=w, fi=efl, fo=eflo))
        elif mn in ('bt', 'bts', 'btr', 'btc', 'bsf'):
            dn = i.reg_name(ops[0].reg)
            dv, w = regval(dn, regs)
            rv, _ = regval(dn, out)
            if mn == 'bsf':
                sv = regval(i.reg_name(ops[1].reg), regs)[0]
                groups[('bsf', w, 'zero' if sv == 0 else 'nz')].append(dict(d=dv, s=sv, r=rv, w=w, fi=efl, fo=eflo))
            else:
                sv = ops[1].imm if ops[1].type == X.X86_OP_IMM else regval(i.reg_name(ops[1].reg), regs)[0]
                groups[(mn, w, '')].append(dict(d=dv, s=sv & (w - 1), r=rv, w=w, fi=efl, fo=eflo))
        elif mn in ('and', 'or', 'xor', 'test'):
            dn = i.reg_name(ops[0].reg)
            dv, w = regval(dn, regs)
            groups[('logic', w, '')].append(dict(d=dv, s=0, r=0, w=w, fi=efl, fo=eflo))

    def F(e, f, which='fo'):
        return (e[which] >> FB[f]) & 1

    def msb(v, w):
        return (v >> (w - 1)) & 1

    hyps = {
        'keep': lambda e, f: F(e, f, 'fi'),
        '0': lambda e, f: 0,
        '1': lambda e, f: 1,
        'P(r)': lambda e, f: P[e['r'] & 0xFF],
        'Z(r)': lambda e, f: int(e['r'] == 0),
        'S(r)': lambda e, f: msb(e['r'], e['w']),
        'msb(r)^cf': lambda e, f: msb(e['r'], e['w']) ^ F(e, 'c'),
        'msb(r)^lsb(r)': lambda e, f: msb(e['r'], e['w']) ^ (e['r'] & 1),
        'msb(r)^msb-1(r)': lambda e, f: msb(e['r'], e['w']) ^ ((e['r'] >> (e['w'] - 2)) & 1),
        'msb(d)': lambda e, f: msb(e['d'], e['w']),
        'msb(d)^msb(r)': lambda e, f: msb(e['d'], e['w']) ^ msb(e['r'], e['w']),
        'msb(d)^cf_in': lambda e, f: msb(e['d'], e['w']) ^ F(e, 'c', 'fi'),
        'bit4(r)': lambda e, f: (e['r'] >> 4) & 1,
        'af(d,s,r)': lambda e, f: ((e['d'] ^ e['s'] ^ e['r']) >> 4) & 1,
        'Z(hi)': lambda e, f: int(e.get('hi', 1) == 0),
        'S(hi)': lambda e, f: msb(e.get('hi', 0), e['w']),
        'P(hi)': lambda e, f: P[e.get('hi', 0) & 0xFF],
        'cf_out': lambda e, f: F(e, 'c'),
        'S(d)': lambda e, f: msb(e['d'], e['w']),
        'P(d)': lambda e, f: P[e['d'] & 0xFF],
        'Z(d)': lambda e, f: int(e['d'] == 0),
        'bit(d,s)': lambda e, f: (e['d'] >> e['s']) & 1,
        'S(lo16)': lambda e, f: (e['r'] >> 15) & 1,
    }
    for key in sorted(groups, key=str):
        es = groups[key]
        line = []
        for f in 'cpazso':
            ok = [h for h, fn in hyps.items() if all(fn(e, f) == F(e, f) for e in es)]
            line.append(f'{f.upper()}:{"|".join(ok[:4]) if ok else "??"}')
        print(f'{str(key):28s} n={len(es):5d} ' + '  '.join(line))


if __name__ == '__main__':
    main()
