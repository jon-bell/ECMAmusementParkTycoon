#!/usr/bin/env python3
"""Mechanical x86 -> JavaScript lifter for rct.exe (Stage 1, docs/stage1-design.md).

  .venv/bin/python lift/lifter.py [--exe game/cd/English/rct.exe] [--map out/spikes/s1v4/cfg.json]
                                  [--hooks lift/hooks.json] [--out out/lift] [--no-flag-opt]
                                  [--single] [--annotate] [--files N]

Reads the user's rct.exe and the static code map v2 (tools/rctcfg.py) and writes one JS function
per basic block into <out>/blocks-*.js plus <out>/manifest.json. The output derives from the
user's binary: it lives under out/ (git-ignored) and is never committed.

Blocks: every map block start and every hook address (lift/hooks.json) starts a block. A block
runs until its first control transfer or until the next block start, and returns the next eip.

Flags: the six arithmetic flags are computed only where live. Liveness is a whole-program
backward analysis over the successors each block's last instruction names (direct jumps,
conditional jumps, fall-through, direct calls: the callee's entry). Returns, indirect jumps and
calls, and int3 make all flags live, so flags are exact wherever control leaves through an
unknown edge. --no-flag-opt computes every flag every time (reference lift).

--single emits one function per instruction start in the map, with every flag computed: the
instruction-level lift used by the CPU differential tests (lift/test/cpu).

Semantics follow the Intel SDM. Where the SDM leaves a flag undefined, the lift reproduces what
the oracle's CPU does (AMD Zen 2), as measured by the native differential harness; see
HW_MODEL below and lift/runtime/ops.js.
"""
import argparse
import hashlib
import json
import os
import sys

import capstone
from capstone import x86 as X
import pefile

IB = 0x400000
CODE_SECTIONS = {'.text': (0x401000, 0x41B1A6), 'CODESEG': (0x41C000, 0x5E6C5D), 'CodeSeg': (0x9B3000, 0x9BC562)}
LIFTER_VERSION = 1

ALL = frozenset('cpazso')          # arithmetic flags: CF PF AF ZF SF OF
FLAG_FIELD = {'c': 'm.cf', 'p': 'm.pf', 'a': 'm.af', 'z': 'm.zf', 's': 'm.sf', 'o': 'm.of'}

R32 = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
R16 = {'ax': 'eax', 'cx': 'ecx', 'dx': 'edx', 'bx': 'ebx', 'sp': 'esp', 'bp': 'ebp', 'si': 'esi', 'di': 'edi'}
R8L = {'al': 'eax', 'cl': 'ecx', 'dl': 'edx', 'bl': 'ebx'}
R8H = {'ah': 'eax', 'ch': 'ecx', 'dh': 'edx', 'bh': 'ebx'}
MASK = {8: '0xFF', 16: '0xFFFF', 32: '0xFFFFFFFF'}
SIGN = {8: '0x80', 16: '0x8000', 32: '0x80000000'}

COND = {  # jcc/setcc suffix -> (JS boolean-ish expression, flags read)
    'o': ('m.of', 'o'), 'no': ('!m.of', 'o'), 'b': ('m.cf', 'c'), 'ae': ('!m.cf', 'c'),
    'e': ('m.zf', 'z'), 'ne': ('!m.zf', 'z'), 'be': ('(m.cf | m.zf)', 'cz'), 'a': ('!(m.cf | m.zf)', 'cz'),
    's': ('m.sf', 's'), 'ns': ('!m.sf', 's'), 'p': ('m.pf', 'p'), 'np': ('!m.pf', 'p'),
    'l': ('(m.sf !== m.of)', 'so'), 'ge': ('(m.sf === m.of)', 'so'),
    'le': ('(m.zf || m.sf !== m.of)', 'zso'), 'g': ('(!m.zf && m.sf === m.of)', 'zso'),
}
JCC = {'j' + k: k for k in COND}
SETCC = {'set' + k: k for k in COND}

# --------------------------------------------------------------------------------------------
# HW_MODEL: flags the SDM leaves undefined, as the oracle's CPU (AMD EPYC 7H12, Zen 2) sets
# them. Each entry is calibrated by lift/test/cpu (native single-step differential harness).
# 'keep' = the flag is left unchanged; otherwise a JS expression over the instruction's
# temporaries. ops.js holds the same model for the helpers (CL-count shifts, mul/div, bsf).
# --------------------------------------------------------------------------------------------
HW_MODEL = {   # measured by lift/test/cpu/flagfit.py on the oracle machine (AMD EPYC 7H12)
    'logic.a': '0',            # AND OR XOR TEST: AF = 0
    'shift.a': '1',            # SHL SHR SAR SHRD with count != 0: AF = 1
    'mul': {},                 # MUL/IMUL: SF ZF AF PF unchanged
    'div': {'p': '0', 'a': '1', 'z': '0', 's': '0'},   # DIV/IDIV: CF OF unchanged (ops.js divFlagsHW)
    'bt': {},                  # BT*: OF SF AF PF (and ZF) unchanged
    'bsf': {},                 # BSF, nonzero source: CF OF SF AF PF unchanged
    'bsf0': {},                # BSF, zero source: CF OF SF AF PF and the destination unchanged
}
# OF for shifts and rotates at every nonzero count (the SDM defines only count 1; the measured
# rule is the count-1 formula generalised): SHL msb(r)^CF, SHR/SHRD msb(r)^msb-1(r), SAR 0,
# ROL msb(r)^CF, ROR/RCR msb(r)^msb-1(r), RCL msb(r)^CF. An 8/16-bit SHL/SHR by more than the
# width (count <= 31) gives CF = 0.


class LiftError(Exception):
    pass


def h(v):
    return '0x%X' % (v & 0xFFFFFFFF)


def norm(expr, w):
    return f'(({expr}) >>> 0)' if w == 32 else f'(({expr}) & {MASK[w]})'


def sx(expr, w):
    """sign-extend a w-bit unsigned value to an int32"""
    if w == 32:
        return f'(({expr}) | 0)'
    return f'(({expr}) << {32 - w} >> {32 - w})'


class Opd:
    """An operand: kind 'reg' | 'mem' | 'imm', width in bits."""

    def __init__(self, kind, w, reg=None, ea=None, imm=None, part=None, uses_esp=False):
        self.kind, self.w, self.reg, self.ea, self.imm, self.part, self.uses_esp = kind, w, reg, ea, imm, part, uses_esp

    def same_reg(self, o):
        return self.kind == 'reg' and o.kind == 'reg' and self.reg == o.reg and self.part == o.part

    def rd(self, a='a'):
        if self.kind == 'imm':
            return h(self.imm & ((1 << self.w) - 1))
        if self.kind == 'mem':
            return f'r{self.w}({a})'
        r = f'm.{self.reg}'
        if self.part == 32:
            return r
        if self.part == 16:
            return f'({r} & 0xFFFF)'
        if self.part == 8:
            return f'({r} & 0xFF)'
        return f'({r} >>> 8 & 0xFF)'   # high byte

    def wr(self, v, a='a'):
        """statement storing v (already a w-bit unsigned value)"""
        if self.kind == 'mem':
            return f'w{self.w}({a}, {v});'
        r = f'm.{self.reg}'
        if self.part == 32:
            return f'{r} = {v};'
        if self.part == 16:
            return f'{r} = ({r} & 0xFFFF0000 | {v}) >>> 0;'
        if self.part == 8:
            return f'{r} = ({r} & 0xFFFFFF00 | {v}) >>> 0;'
        return f'{r} = ({r} & 0xFFFF00FF | {v} << 8) >>> 0;'


class Lifter:
    def __init__(self, exe, cfg, hooks, flag_opt=True, annotate=False):
        pe = pefile.PE(exe)
        self.img = pe.get_memory_mapped_image()
        with open(exe, 'rb') as f:
            self.md5 = hashlib.md5(f.read()).hexdigest()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.cfg = cfg
        self.cache = {}
        self.istarts = set(cfg['instruction_starts'])
        self.hooks = hooks
        self.derived = self.derive_leaders()
        self.leaders = sorted(set(cfg['blocks']) | set(hooks) | self.derived)
        self.leader_set = set(self.leaders)
        self.flag_opt = flag_opt
        self.annotate = annotate
        self.stats = {'insns': 0, 'blocks': 0}
        for a in hooks:
            if a not in self.istarts:
                raise LiftError(f'hook {h(a)} is not an instruction start in the map')

    def derive_leaders(self):
        """Block starts implied by the map's own instructions: direct branch targets and the
        instruction after every transfer. The map (tools/rctcfg.py) misses those of `loop`, which
        capstone does not put in its jump group; deriving them here is sound because every such
        address must already be an instruction start (checked)."""
        out = set()
        for a in self.istarts:
            i = self.insn(a)
            if not is_transfer(i):
                continue
            nxt = a + i.size
            if i.mnemonic != 'jmp' and i.mnemonic != 'ret' and nxt in self.istarts:
                out.add(nxt)
            if i.mnemonic in JCC or i.mnemonic in ('jmp', 'call', 'loop', 'jcxz', 'jecxz'):
                if i.operands[0].type == X.X86_OP_IMM:
                    t = target(i)
                    if CODE_SECTIONS_ANY(t):
                        if t not in self.istarts:
                            raise LiftError(f'{h(a)}: branch target {h(t)} is not an instruction start in the map')
                        out.add(t)
        return out - set(self.cfg['blocks'])

    # ---------------- decoding ----------------
    def insn(self, a):
        i = self.cache.get(a)
        if i is None:
            sec = next((s for s, (lo, hi) in CODE_SECTIONS.items() if lo <= a < hi), None)
            if sec is None:
                raise LiftError(f'{h(a)} outside code sections')
            hi = CODE_SECTIONS[sec][1]
            i = next(self.md.disasm(bytes(self.img[a - IB:min(a - IB + 16, hi - IB)]), a, 1), None)
            if i is None:
                raise LiftError(f'{h(a)}: undecodable')
            self.cache[a] = i
        return i

    def block_insns(self, a0):
        out = []
        a = a0
        while True:
            if a not in self.istarts:
                raise LiftError(f'block {h(a0)}: {h(a)} is not an instruction start in the map')
            i = self.insn(a)
            out.append(i)
            if is_transfer(i):
                return out
            a = a + i.size
            if a in self.leader_set:
                return out

    # ---------------- operands ----------------
    def opd(self, i, o):
        if o.type == X.X86_OP_REG:
            n = i.reg_name(o.reg)
            if n in R32:
                return Opd('reg', 32, reg=n, part=32)
            if n in R16:
                return Opd('reg', 16, reg=R16[n], part=16)
            if n in R8L:
                return Opd('reg', 8, reg=R8L[n], part=8)
            if n in R8H:
                return Opd('reg', 8, reg=R8H[n], part='h')
            raise LiftError(f'{h(i.address)}: register {n} unsupported')
        if o.type == X.X86_OP_IMM:
            return Opd('imm', o.size * 8, imm=o.imm)
        if o.type == X.X86_OP_MEM:
            return Opd('mem', o.size * 8, ea=self.ea(i, o), uses_esp=self.mem_uses(i, o, 'esp'))
        raise LiftError(f'{h(i.address)}: operand type {o.type}')

    def mem_uses(self, i, o, reg):
        return (o.mem.base and i.reg_name(o.mem.base) == reg) or (o.mem.index and i.reg_name(o.mem.index) == reg)

    def ea(self, i, o):
        if i.prefix[3] == 0x67:
            raise LiftError(f'{h(i.address)}: 16-bit addressing unsupported')
        mm = o.mem
        terms = []
        seg = i.reg_name(mm.segment) if mm.segment else None
        if seg == 'fs':
            terms.append('m.fsBase')
        elif seg not in (None, 'cs', 'ds', 'es', 'ss'):
            raise LiftError(f'{h(i.address)}: segment {seg} unsupported')
        if mm.base:
            b = i.reg_name(mm.base)
            if b not in R32:
                raise LiftError(f'{h(i.address)}: base {b}')
            terms.append(f'm.{b}')
        if mm.index:
            x = i.reg_name(mm.index)
            if x not in R32:
                raise LiftError(f'{h(i.address)}: index {x}')
            terms.append(f'm.{x}' if mm.scale == 1 else f'm.{x} * {mm.scale}')
        disp = mm.disp & 0xFFFFFFFF
        if not terms:
            return h(disp)
        if disp:
            sd = disp - (1 << 32) if disp & 0x80000000 else disp
            terms.append(str(sd) if sd < 0 else h(sd))
        if len(terms) == 1:
            return terms[0]      # a single register: already uint32
        e = ' + '.join(terms).replace('+ -', '- ')
        return f'({e}) >>> 0'

    # ---------------- flags ----------------
    def flag_info(self, i):
        """(use, must_def) sets of arithmetic flags."""
        mn = i.mnemonic
        base = mn.split()[-1]
        if mn in JCC or mn in SETCC:
            return set(COND[(JCC.get(mn) or SETCC.get(mn))][1]), set()
        if mn in ('add', 'sub', 'cmp', 'and', 'or', 'xor', 'test', 'neg'):
            return set(), set(ALL)
        if mn in ('adc', 'sbb'):
            return {'c'}, set(ALL)
        if mn in ('inc', 'dec'):
            return set(), set('pazso')
        if mn in ('shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'shrd', 'shld'):
            c = shift_count(i)
            if c is None:                      # count in cl: may leave every flag unchanged
                return set(ALL), set()
            return shift_flags(mn, c, self.opd(i, i.operands[0]).w)
        if mn in ('mul', 'imul'):
            return set(), {'c', 'o'} | set(HW_MODEL['mul'])
        if mn in ('div', 'idiv'):
            return set(), set(HW_MODEL['div'])
        if mn in ('bt', 'bts', 'btr', 'btc'):
            return set(), {'c'} | set(HW_MODEL['bt'])
        if mn == 'bsf':
            return set(), {'z'} | (set(HW_MODEL['bsf']) & set(HW_MODEL['bsf0']))
        if mn in ('stc', 'clc'):
            return set(), {'c'}
        if mn in ('pushf', 'pushfd'):
            return set(ALL), set()
        if mn in ('popf', 'popfd'):
            return set(), set(ALL)
        if base in ('scasb', 'scasw', 'scasd', 'cmpsb', 'cmpsw', 'cmpsd'):
            if mn.startswith('rep'):
                return set(ALL), set()          # ecx == 0: flags unchanged
            return set(), set(ALL)
        return set(), set()

    # ---------------- code generation ----------------
    def lift_insn(self, i, live):
        """JS statements for one instruction. `live`: flags needed after it.
        Returns (lines, terminator) where terminator is a JS return statement or None."""
        mn = i.mnemonic
        nxt = i.address + i.size
        ops = [self.opd(i, o) for o in i.operands] if mn.split()[-1] not in STRING_OPS else []
        L = []
        g = Gen(L, live, i)

        if mn in JCC:
            return L, f'return {COND[JCC[mn]][0]} ? {h(target(i))} : {h(nxt)};'
        if mn == 'jmp':
            o = i.operands[0]
            if o.type == X.X86_OP_IMM:
                return L, f'return {h(target(i))};'
            d = ops[0]
            if d.kind == 'mem':
                if not (o.mem.base or o.mem.index):          # jmp [disp32]: import thunks
                    return L + [f'm.xslot = {h(o.mem.disp)};'], f'return r32({d.ea});'
                return L, f'return r32({d.ea});'
            return L + ['m.xslot = 0;'], f'return {d.rd()};'
        if mn == 'call':
            o = i.operands[0]
            if o.type == X.X86_OP_IMM:
                L.append(f'{{ const s = (m.esp - 4) >>> 0; w32(s, {h(nxt)}); m.esp = s; }}')
                return L, f'return {h(target(i))};'
            d = ops[0]
            tgt = f'r32({d.ea})' if d.kind == 'mem' else d.rd()
            # m.xslot: the [disp32] slot of an indirect call, else 0 (register capture `O` records)
            slot = h(o.mem.disp) if d.kind == 'mem' and not (o.mem.base or o.mem.index) else '0'
            L.append(f'const t = {tgt}; {{ const s = (m.esp - 4) >>> 0; w32(s, {h(nxt)}); m.esp = s; }} m.xslot = {slot};')
            return L, 'return t;'
        if mn == 'ret':
            n = i.operands[0].imm if i.operands else 0
            L.append(f'const t = r32(m.esp); m.esp = (m.esp + {4 + n}) >>> 0;')
            return L, 'return t;'
        if mn in ('loop', 'jcxz', 'jecxz'):
            a16 = i.prefix[3] == 0x67
            if mn == 'loop':
                if a16:
                    L.append('const c = (m.ecx - 1) & 0xFFFF; m.ecx = (m.ecx & 0xFFFF0000 | c) >>> 0;')
                else:
                    L.append('const c = (m.ecx - 1) >>> 0; m.ecx = c;')
                return L, f'return c !== 0 ? {h(target(i))} : {h(nxt)};'
            if mn == 'jcxz' or a16:
                return L, f'return (m.ecx & 0xFFFF) === 0 ? {h(target(i))} : {h(nxt)};'
            return L, f'return m.ecx === 0 ? {h(target(i))} : {h(nxt)};'
        if mn == 'int3':
            return L, f'return int3(m, {h(i.address)});'

        if mn == 'mov':
            d, s = ops
            if d.kind == 'mem':
                L.append(f'{{ const a = {d.ea}; {d.wr(s.rd("x"), "a")} }}')
            else:
                L.append(d.wr(s.rd(s.ea) if s.kind == 'mem' else s.rd()))
            return L, None
        if mn in ('movzx', 'movsx'):
            d, s = ops
            v = s.rd(s.ea) if s.kind == 'mem' else s.rd()
            if mn == 'movsx':
                v = norm(sx(v, s.w), d.w)
            L.append(d.wr(v))
            return L, None
        if mn == 'lea':
            d, s = ops
            if d.w != 32:
                raise LiftError(f'{h(i.address)}: lea r16')
            L.append(d.wr(s.ea))
            return L, None
        if mn == 'xchg':
            d, s = ops
            if d.kind == 'mem' or s.kind == 'mem':
                mo, ro = (d, s) if d.kind == 'mem' else (s, d)
                L.append(f'{{ const a = {mo.ea}; const x = {mo.rd("a")}; {mo.wr(ro.rd(), "a")} {ro.wr("x")} }}')
            else:
                L.append(f'{{ const x = {d.rd()}, y = {s.rd()}; {d.wr("y")} {s.wr("x")} }}')
            return L, None
        if mn == 'push':
            s = ops[0]
            w = 16 if i.prefix[2] == 0x66 else 32
            if s.kind == 'imm':
                v = h(s.imm & ((1 << w) - 1))
            elif s.kind == 'mem':
                v = f'r{w}({s.ea})'
            else:
                v = s.rd()
            k = w // 8
            L.append(f'{{ const v = {v}, s = (m.esp - {k}) >>> 0; w{w}(s, v); m.esp = s; }}')
            return L, None
        if mn == 'pop':
            d = ops[0]
            w = d.w
            k = w // 8
            if d.kind == 'mem':
                # the destination address is computed after esp is incremented (SDM: POP)
                L.append(f'{{ const v = r{w}(m.esp); m.esp = (m.esp + {k}) >>> 0; w{w}({d.ea}, v); }}')
            else:
                L.append(f'{{ const v = r{w}(m.esp); m.esp = (m.esp + {k}) >>> 0; {d.wr("v")} }}')
            return L, None
        if mn == 'pushal':
            L.append('{ const s = m.esp; w32((s - 4) >>> 0, m.eax); w32((s - 8) >>> 0, m.ecx); w32((s - 12) >>> 0, m.edx); '
                     'w32((s - 16) >>> 0, m.ebx); w32((s - 20) >>> 0, s); w32((s - 24) >>> 0, m.ebp); '
                     'w32((s - 28) >>> 0, m.esi); w32((s - 32) >>> 0, m.edi); m.esp = (s - 32) >>> 0; }')
            return L, None
        if mn == 'popal':
            L.append('{ const s = m.esp; m.edi = r32(s); m.esi = r32((s + 4) >>> 0); m.ebp = r32((s + 8) >>> 0); '
                     'm.ebx = r32((s + 16) >>> 0); m.edx = r32((s + 20) >>> 0); m.ecx = r32((s + 24) >>> 0); '
                     'm.eax = r32((s + 28) >>> 0); m.esp = (s + 32) >>> 0; }')
            return L, None
        if mn in ('pushf', 'pushfd'):
            w = 16 if mn == 'pushf' else 32
            L.append(f'{{ const v = m.getEflags(){" & 0xFFFF" if w == 16 else " & 0x00FCFFFF"}, s = (m.esp - {w // 8}) >>> 0; '
                     f'w{w}(s, v); m.esp = s; }}')
            return L, None
        if mn in ('popf', 'popfd'):
            w = 16 if mn == 'popf' else 32
            L.append(f'{{ const v = r{w}(m.esp); m.esp = (m.esp + {w // 8}) >>> 0; m.setEflags(v); }}')
            return L, None
        if mn == 'leave':
            L.append('{ const v = r32(m.ebp); m.esp = (m.ebp + 4) >>> 0; m.ebp = v; }')
            return L, None
        if mn == 'cdq':
            L.append('m.edx = m.eax >>> 31 ? 0xFFFFFFFF : 0;')
            return L, None
        if mn == 'cwd':
            L.append('m.edx = (m.edx & 0xFFFF0000 | (m.eax & 0x8000 ? 0xFFFF : 0)) >>> 0;')
            return L, None
        if mn == 'cwde':
            L.append('m.eax = (m.eax << 16 >> 16) >>> 0;')
            return L, None
        if mn == 'cbw':
            L.append('m.eax = (m.eax & 0xFFFF0000 | (m.eax << 24 >> 24) & 0xFFFF) >>> 0;')
            return L, None
        if mn == 'stc':
            if 'c' in live:
                L.append('m.cf = 1;')
            return L, None
        if mn == 'clc':
            if 'c' in live:
                L.append('m.cf = 0;')
            return L, None
        if mn == 'std':
            L.append('m.df = 1;')
            return L, None
        if mn == 'cld':
            L.append('m.df = 0;')
            return L, None
        if mn in ('nop', 'wait'):
            return L, None
        if mn in SETCC:
            L.append(ops[0].wr(f'({COND[SETCC[mn]][0]} ? 1 : 0)', ops[0].ea if ops[0].kind == 'mem' else 'a'))
            return L, None

        if mn in ('add', 'sub', 'adc', 'sbb', 'cmp', 'and', 'or', 'xor', 'test'):
            g.binop(mn, *ops)
            return L, None
        if mn in ('inc', 'dec', 'neg', 'not'):
            g.unop(mn, ops[0])
            return L, None
        if mn in ('shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr'):
            g.shift(mn, ops[0], shift_count(i))
            return L, None
        if mn == 'shrd' or mn == 'shld':
            g.shiftd(mn, ops[0], ops[1], shift_count(i))
            return L, None
        if mn in ('mul', 'imul', 'div', 'idiv'):
            g.muldiv(mn, ops)
            return L, None
        if mn in ('bt', 'bts', 'btr', 'btc'):
            g.bittest(mn, ops[0], ops[1])
            return L, None
        if mn == 'bsf':
            g.bsf(ops[0], ops[1])
            return L, None
        base = mn.split()[-1]
        if base in STRING_OPS:
            g.string(mn, base)
            return L, None
        if mn in X87:
            g.x87(mn, ops)
            return L, None
        if mn == 'cpuid':
            L.append('cpuid(m);')
            return L, None
        raise LiftError(f'{h(i.address)}: unsupported instruction {mn} {i.op_str}')

    def lift_block(self, a0, insns, live_out):
        # backward liveness inside the block
        lives = [None] * len(insns)
        live = set(live_out)
        for k in range(len(insns) - 1, -1, -1):
            lives[k] = frozenset(live) if self.flag_opt else ALL
            use, d = self.flag_info(insns[k])
            live = (live - d) | use
        body = []
        term = None
        for k, i in enumerate(insns):
            lines, t = self.lift_insn(i, lives[k])
            if self.annotate:
                body.append(f'  // {i.address:08X} {i.mnemonic} {i.op_str}  live:{"".join(sorted(lives[k]))}')
            if lines:
                if t is None:
                    body.append('  { ' + ' '.join(lines) + ' }')
                else:
                    body.append('  ' + ' '.join(lines))
            if t is not None:
                term = t
        if term is None:
            last = insns[-1]
            term = f'return {h(last.address + last.size)};'
        body.append('  ' + term)
        return body


STRING_OPS = {'movsb', 'movsw', 'movsd', 'stosb', 'stosw', 'stosd', 'scasb', 'scasw', 'scasd', 'lodsb', 'lodsw', 'lodsd',
              'cmpsb', 'cmpsw', 'cmpsd'}
X87 = {'fld', 'fstp', 'fmul', 'fdiv', 'fsubr', 'fcomp', 'fnstsw', 'fnstcw', 'fldcw', 'fnclex'}



def CODE_SECTIONS_ANY(a):
    return any(lo <= a < hi for lo, hi in CODE_SECTIONS.values())


def is_transfer(i):
    return i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL) or i.mnemonic in ('ret', 'int3', 'loop')


def target(i):
    return i.operands[0].imm & 0xFFFFFFFF


def shift_count(i):
    """Static count of a shift/rotate (masked to 5 bits), or None if it is in cl."""
    o = i.operands[-1]
    if len(i.operands) == 1:
        return 1
    if o.type == X.X86_OP_IMM:
        return o.imm & 31
    return None


def shift_flags(mn, c, w):
    """(use, must_def) for a shift by a static count (consistent with Gen.shift)."""
    if c == 0:
        return set(), set()
    if mn in ('rol', 'ror'):
        return set(), {'c', 'o'}
    if mn in ('rcl', 'rcr'):
        k = c % (w + 1) if w < 32 else c
        if k == 0:
            return {'c'}, {'o'}            # no rotation: CF unchanged, OF computed from it
        return {'c'}, {'c', 'o'}
    return set(), set(ALL)


class Gen:
    """Emits JS for one instruction into L, computing only flags in `live`."""

    def __init__(self, L, live, i):
        self.L, self.live, self.i = L, live, i

    def flags(self, d):
        """d: flag -> JS expression. Emit the live ones."""
        out = []
        for f in 'cpazso':
            if f in d and f in self.live:
                out.append(f'{FLAG_FIELD[f]} = {d[f]};')
        return ' '.join(out)

    def szp(self, w, r='r'):
        return {'z': f'+({r} === 0)', 's': f'{r} >>> {w - 1}', 'p': f'P[{r} & 0xFF]'}

    def operand_setup(self, d):
        """If d is memory, compute its address once into `a`."""
        return f'const a = {d.ea}; ' if d.kind == 'mem' else ''

    def binop(self, mn, d, s):
        w = d.w
        if s.kind == 'imm':
            s = Opd('imm', w, imm=s.imm)      # imm8 sign-extended to the operand width
        M = MASK[w]
        live = self.live
        writes = mn not in ('cmp', 'test')
        # x op x with the same register
        if d.same_reg(s) and mn in ('xor', 'sub'):
            fl = {'c': '0', 'p': '1', 'z': '1', 's': '0', 'o': '0', 'a': '0' if mn == 'sub' else HW_MODEL['logic.a']}
            self.L.append(d.wr('0') + ' ' + self.flags(fl))
            return
        need_flags = bool(live & ALL)
        if not writes and not need_flags:
            return
        pre = self.operand_setup(d)
        sv = f'r{w}({s.ea})' if s.kind == 'mem' else s.rd()
        code = [pre + f'const d = {d.rd()}, s = {sv};']
        fl = {}
        if mn in ('add', 'adc'):
            cin = ' + m.cf' if mn == 'adc' else ''
            code.append(f'const t = d + s{cin}, r = {"t >>> 0" if w == 32 else "t & " + M};')
            fl = {'c': f'+(t > {M})', 'o': f'((d ^ r) & (s ^ r)) >>> {w - 1} & 1', 'a': '(d ^ s ^ r) >>> 4 & 1'}
        elif mn in ('sub', 'sbb', 'cmp'):
            if mn == 'sbb':
                code.append(f'const ci = m.cf, t = d - s - ci, r = {"t >>> 0" if w == 32 else "t & " + M};')
                fl = {'c': '+(d < s + ci)'}
            else:
                code.append(f'const r = {"(d - s) >>> 0" if w == 32 else "(d - s) & " + M};')
                fl = {'c': '+(d < s)'}
            fl.update({'o': f'((d ^ s) & (d ^ r)) >>> {w - 1} & 1', 'a': '(d ^ s ^ r) >>> 4 & 1'})
        else:
            op = {'and': '&', 'test': '&', 'or': '|', 'xor': '^'}[mn]
            code.append(f'const r = {norm(f"d {op} s", w) if w == 32 else f"d {op} s"};')
            fl = {'c': '0', 'o': '0', 'a': HW_MODEL['logic.a']}
        fl.update(self.szp(w))
        if writes:
            code.append(d.wr('r'))
        code.append(self.flags(fl))
        self.L.append(' '.join(c for c in code if c))

    def unop(self, mn, d):
        w = d.w
        M = MASK[w]
        pre = self.operand_setup(d)
        if mn == 'not':
            self.L.append(pre + d.wr(f'(~{d.rd()} & {M})' if w < 32 else f'(~{d.rd()} >>> 0)'))
            return
        code = [pre + f'const d = {d.rd()};']
        if mn == 'inc':
            code.append(f'const r = {"(d + 1) >>> 0" if w == 32 else "(d + 1) & " + M};')
            fl = {'o': f'+(r === {SIGN[w]})', 'a': '+((r & 0xF) === 0)'}
        elif mn == 'dec':
            code.append(f'const r = {"(d - 1) >>> 0" if w == 32 else "(d - 1) & " + M};')
            fl = {'o': f'+(d === {SIGN[w]})', 'a': '+((d & 0xF) === 0)'}
        else:  # neg
            code.append(f'const r = {"(-d) >>> 0" if w == 32 else "(-d) & " + M};')
            fl = {'c': '+(d !== 0)', 'o': f'+(d === {SIGN[w]})', 'a': '(d ^ r) >>> 4 & 1'}
        fl.update(self.szp(w))
        code.append(d.wr('r'))
        code.append(self.flags(fl))
        self.L.append(' '.join(c for c in code if c))

    def shift(self, mn, d, c):
        w = d.w
        M = MASK[w]
        pre = self.operand_setup(d)
        if c is None:
            # count in cl: runtime helper computes result and every flag (when count != 0)
            fn = {'sal': 'shl'}.get(mn, mn)
            self.L.append(pre + f'const r = {fn}{w}(m, {d.rd()}, m.ecx & 0xFF); {d.wr("r")}')
            return
        if c == 0:
            return
        code = [pre + f'const d = {d.rd()};']
        fl = {}
        if mn in ('shl', 'sal'):
            code.append(f'const r = {norm(f"d << {c}", w)};')
            if c <= w:
                fl['c'] = f'd >>> {w - c} & 1'
            else:
                fl['c'] = hw_shift_cf('shl', w, c)
            fl['o'] = f'(r >>> {w - 1}) ^ ({fl["c"]})'
            fl['a'] = HW_MODEL['shift.a']
            fl.update(self.szp(w))
        elif mn == 'shr':
            code.append(f'const r = d >>> {c};' if c < 32 else 'const r = 0;')
            fl['c'] = f'd >>> {c - 1} & 1' if c <= w else hw_shift_cf('shr', w, c)
            fl['o'] = f'(r >>> {w - 1}) ^ (r >>> {w - 2} & 1)'
            fl['a'] = HW_MODEL['shift.a']
            fl.update(self.szp(w))
        elif mn == 'sar':
            code.append(f'const ds = {sx("d", w)}, r = {norm(f"ds >> {c}", w)};')
            fl['c'] = f'ds >> {min(c - 1, 31)} & 1'
            fl['o'] = '0'
            fl['a'] = HW_MODEL['shift.a']
            fl.update(self.szp(w))
        elif mn in ('rol', 'ror'):
            k = c % w
            if k == 0:
                code.append('const r = d;')
            elif mn == 'rol':
                code.append(f'const r = {norm(f"d << {k} | d >>> {w - k}", w)};')
            else:
                code.append(f'const r = {norm(f"d >>> {k} | d << {w - k}", w)};')
            if mn == 'rol':
                fl['c'] = 'r & 1'
                fl['o'] = f'(r >>> {w - 1}) ^ (r & 1)'
            else:
                fl['c'] = f'r >>> {w - 1}'
                fl['o'] = f'(r >>> {w - 1}) ^ (r >>> {w - 2} & 1)'
        elif mn in ('rcl', 'rcr'):
            k = c % (w + 1) if w < 32 else c
            if k == 0:
                code.append('const r = d;')       # no rotation: CF unchanged
                fl['o'] = f'(r >>> {w - 1}) ^ m.cf' if mn == 'rcl' else f'(r >>> {w - 1}) ^ (r >>> {w - 2} & 1)'
            else:
                code.append('const ci = m.cf;')
                if w < 32:
                    W1 = (1 << (w + 1)) - 1
                    code.append(f'const x = ci << {w} | d;')
                    if mn == 'rcl':
                        code.append(f'const y = (x << {k} | x >>> {w + 1 - k}) & {h(W1)};')
                    else:
                        code.append(f'const y = (x >>> {k} | x << {w + 1 - k}) & {h(W1)};')
                    code.append(f'const r = y & {M}, co = y >>> {w};')
                else:
                    if mn == 'rcl':
                        if k == 1:
                            code.append('const r = (d << 1 | ci) >>> 0, co = d >>> 31;')
                        else:
                            code.append(f'const r = (d << {k} | ci << {k - 1} | d >>> {33 - k}) >>> 0, co = d >>> {32 - k} & 1;')
                    else:
                        if k == 1:
                            code.append('const r = (d >>> 1 | ci << 31) >>> 0, co = d & 1;')
                        else:
                            code.append(f'const r = (d >>> {k} | ci << {32 - k} | d << {33 - k}) >>> 0, co = d >>> {k - 1} & 1;')
                fl['c'] = 'co'
                fl['o'] = f'(r >>> {w - 1}) ^ co' if mn == 'rcl' else f'(r >>> {w - 1}) ^ (r >>> {w - 2} & 1)'
        else:
            raise LiftError(f'{h(self.i.address)}: shift {mn}')
        code.append(d.wr('r'))
        code.append(self.flags({k_: v for k_, v in fl.items() if v != 'keep'}))
        self.L.append(' '.join(x for x in code if x))

    def shiftd(self, mn, d, s, c):
        w = d.w
        if w != 32 or mn != 'shrd':
            raise LiftError(f'{h(self.i.address)}: {mn} r{w} unsupported')
        pre = self.operand_setup(d)
        if c is None:
            self.L.append(pre + f'const r = shrd32(m, {d.rd()}, {s.rd()}, m.ecx & 0xFF); {d.wr("r")}')
            return
        if c == 0:
            return
        code = [pre + f'const d = {d.rd()}, s = {s.rd()};',
                f'const r = (d >>> {c} | s << {32 - c}) >>> 0;']
        fl = {'c': f'd >>> {c - 1} & 1', 'o': '(r >>> 31) ^ (r >>> 30 & 1)', 'a': HW_MODEL['shift.a']}
        fl.update(self.szp(32))
        code.append(d.wr('r'))
        code.append(self.flags({k_: v for k_, v in fl.items() if v != 'keep'}))
        self.L.append(' '.join(code))

    def muldiv(self, mn, ops):
        i = self.i
        L = self.L
        if mn in ('div', 'idiv'):
            s = ops[0]
            v = f'r{s.w}({s.ea})' if s.kind == 'mem' else s.rd()
            L.append(f'{mn}{s.w}(m, {v}, {h(i.address)});')
            return
        if mn == 'mul' or (mn == 'imul' and len(ops) == 1):
            s = ops[0]
            v = f'r{s.w}({s.ea})' if s.kind == 'mem' else s.rd()
            L.append(f'{mn}{s.w}(m, {v});')
            return
        # imul r, r/m [, imm]
        d = ops[0]
        a, b = (ops[0], ops[1]) if len(ops) == 2 else (ops[1], ops[2])
        w = d.w
        av = f'r{a.w}({a.ea})' if a.kind == 'mem' else a.rd()
        if b.kind == 'imm':
            bv = str(signed(b.imm, 32))
            if w == 16:
                bv = str(signed(b.imm & 0xFFFF, 16))
        else:
            bv = f'r{b.w}({b.ea})' if b.kind == 'mem' else b.rd()
        code = []
        if w == 32:
            code.append(f'const x = {av} | 0, y = {bv} | 0, r = Math.imul(x, y) >>> 0;')
            ov = '+(x * y !== (r | 0))'
        else:
            code.append(f'const x = {sx(av, 16)}, y = {sx(bv, 16) if b.kind != "imm" else bv}, p = x * y, r = p & 0xFFFF;')
            ov = '+(p !== (p << 16 >> 16))'
        code.append(d.wr('r'))
        fl = {'c': ov, 'o': ov}
        fl.update(hw_mul_szap(w))
        code.append(self.flags(fl))
        L.append(' '.join(c for c in code if c))

    def bittest(self, mn, d, s):
        w = d.w
        code = []
        if d.kind == 'mem' and s.kind == 'reg':
            o = sx(s.rd(), w) if w == 16 else f'({s.rd()} | 0)'
            sh = 4 if w == 16 else 5
            code.append(f'const o = {o}, a = (({d.ea}) + (o >> {sh}) * {w // 8}) >>> 0, b = o & {w - 1};')
        else:
            if d.kind == 'mem':
                code.append(f'const a = {d.ea};')
            ov = h(s.imm & (w - 1)) if s.kind == 'imm' else f'{s.rd()} & {w - 1}'
            code.append(f'const b = {ov};')
        code.append(f'const d = {d.rd("a")};')
        fl = {'c': 'd >>> b & 1'}
        fl.update(hw_bt_flags(w))
        # CF must be computed before d is replaced
        code.append(self.flags(fl))
        if mn != 'bt':
            bit = '(1 << b)'
            expr = {'bts': f'd | {bit}', 'btr': f'd & ~{bit}', 'btc': f'd ^ {bit}'}[mn]
            code.append(d.wr(norm(expr, w), 'a'))
        self.L.append(' '.join(c for c in code if c))

    def bsf(self, d, s):
        w = d.w
        v = f'r{s.w}({s.ea})' if s.kind == 'mem' else s.rd()
        self.L.append(f'const s = {v}; if (s === 0) {{ m.zf = 1; {hw_bsf_zero(w)} }} else {{ m.zf = 0; '
                      f'const r = 31 - Math.clz32(s & -s); {d.wr("r")} {self.flags(hw_bsf_flags(w))} }}')

    def string(self, mn, base):
        i = self.i
        w = {'b': 8, 'w': 16, 'd': 32}[base[-1]]
        rep = 'rep' if i.prefix[0] == 0xF3 else ('repne' if i.prefix[0] == 0xF2 else '')
        op = base[:-1]
        if op not in ('movs', 'stos', 'scas'):
            raise LiftError(f'{h(i.address)}: string op {mn}')
        if op == 'scas' and rep != 'repne' and rep != '':
            raise LiftError(f'{h(i.address)}: {mn}')
        fn = {'movs': 'movs', 'stos': 'stos', 'scas': 'scas'}[op]
        r = {'rep': 'Rep', 'repne': 'Repne', '': ''}[rep]
        self.L.append(f'{fn}{w}{r}(m);')

    def x87(self, mn, ops):
        if mn in ('fld', 'fstp', 'fmul', 'fdiv', 'fsubr', 'fcomp'):
            o = ops[0]
            if o.kind != 'mem' or o.w != 64:
                raise LiftError(f'{h(self.i.address)}: {mn} form')
            self.L.append(f'{mn}64(m, {o.ea});')
        elif mn == 'fnstsw':
            o = ops[0]
            if not (o.kind == 'reg' and o.part == 16 and o.reg == 'eax'):
                raise LiftError(f'{h(self.i.address)}: fnstsw form')
            self.L.append('m.eax = (m.eax & 0xFFFF0000 | fnstsw(m)) >>> 0;')
        elif mn == 'fnstcw':
            self.L.append(f'w16({ops[0].ea}, m.fpu.cw);')
        elif mn == 'fldcw':
            self.L.append(f'fldcw(m, r16({ops[0].ea}));')
        elif mn == 'fnclex':
            self.L.append('m.fpu.sw &= 0x7F00;')
        else:
            raise LiftError(mn)


def signed(v, w):
    v &= (1 << w) - 1
    return v - (1 << w) if v >> (w - 1) else v


# ---- HW_MODEL hooks (undefined flags) ----
def hw_shift_cf(mn, w, c):
    # shl/shr of an 8/16-bit operand by more than its width (c <= 31): measured CF = 0
    return '0'


def hw_mul_szap(w):
    return dict(HW_MODEL['mul'])


def hw_bt_flags(w):
    return dict(HW_MODEL['bt'])


def hw_bsf_zero(w):
    return ' '.join(f'{FLAG_FIELD[f]} = {v};' for f, v in HW_MODEL['bsf0'].items())


def hw_bsf_flags(w):
    return dict(HW_MODEL['bsf'])


# --------------------------------------------------------------------------------------------
def successors(lf, i):
    """Successor block addresses of a block whose last instruction is i, or None = unknown (all live)."""
    mn = i.mnemonic
    nxt = i.address + i.size
    if mn in JCC or mn in ('loop', 'jcxz', 'jecxz'):
        return [target(i), nxt]
    if mn == 'jmp':
        return [target(i)] if i.operands[0].type == X.X86_OP_IMM else None
    if mn == 'call':
        return [target(i)] if i.operands[0].type == X.X86_OP_IMM else None
    if mn in ('ret', 'int3'):
        return None
    return [nxt]


def liveness(lf, blocks):
    """Global backward analysis: live-in flag set of every block. Hook addresses have every flag
    live-in, so the flags are exact whenever a hook runs."""
    hook_set = set(lf.hooks)
    succ = {}
    gen = {}
    kill = {}
    for a, insns in blocks.items():
        s = successors(lf, insns[-1])
        succ[a] = None if s is None or any(x not in blocks for x in s) else s
        live_use = set()
        k_ = set()
        for i in insns:                       # forward: use before def
            u, d = lf.flag_info(i)
            live_use |= (u - k_)
            k_ |= d
        gen[a], kill[a] = frozenset(live_use), frozenset(k_)
        if a in hook_set:
            # hooks observe flags (TR_REGS_IN3 records eflags at 0x426F56): exact at every hook
            gen[a] = ALL
    live_in = {a: frozenset() for a in blocks}
    preds = {a: [] for a in blocks}
    for a, s in succ.items():
        if s:
            for x in s:
                preds[x].append(a)
    work = list(blocks)
    inq = set(work)
    while work:
        a = work.pop()
        inq.discard(a)
        out = ALL if succ[a] is None else frozenset().union(*(live_in[x] for x in succ[a]))
        new = gen[a] | (out - kill[a])
        if new != live_in[a]:
            live_in[a] = new
            for p in preds[a]:
                if p not in inq:
                    inq.add(p)
                    work.append(p)
    live_out = {a: (ALL if succ[a] is None else frozenset().union(*(live_in[x] for x in succ[a]))) for a in blocks}
    return live_in, live_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default='game/cd/English/rct.exe')
    ap.add_argument('--map', default='out/spikes/s1v4/cfg.json')
    ap.add_argument('--hooks', default=os.path.join(os.path.dirname(__file__), 'hooks.json'))
    ap.add_argument('--out', default='out/lift')
    ap.add_argument('--no-flag-opt', action='store_true')
    ap.add_argument('--single', action='store_true', help='one function per instruction (all flags)')
    ap.add_argument('--annotate', action='store_true', help='disassembly comments in the output')
    ap.add_argument('--files', type=int, default=16)
    ap.add_argument('--insns', help='JSON [{addr, hex}]: lift these instruction bytes (implies --single)')
    ap.add_argument('--region-bits', type=int, default=7,
                    help='also emit region functions grouping the blocks of each 2^N-byte code window '
                         '(0: none). Hook addresses stay single blocks.')
    ap.add_argument('--region-max', type=int, default=100, help='max instructions per region function')
    args = ap.parse_args()
    if args.insns:
        args.single = True

    cfg = json.load(open(args.map))
    hooks = [int(x['addr'], 16) for x in json.load(open(args.hooks))['hooks']]
    lf = Lifter(args.exe, cfg, hooks, flag_opt=not (args.no_flag_opt or args.single), annotate=args.annotate)
    if cfg.get('binary_md5') != lf.md5:
        raise LiftError('map was built from a different binary')
    os.makedirs(args.out, exist_ok=True)
    errors = []
    units = []            # (addr, ninsn, body lines)
    if args.insns:
        lf.istarts = set()
        for e in json.load(open(args.insns)):
            a, code = e['addr'], bytes.fromhex(e['hex'])
            i = next(lf.md.disasm(code + b'\x90' * 16, a, 1))
            if i.size != len(code):
                errors.append(f'{h(a)}: {e["hex"]} decodes as {i.size} bytes')
            lf.cache[a] = i
            lf.istarts.add(a)
    if args.single:
        for a in sorted(lf.istarts):
            i = lf.insn(a)
            try:
                lines, t = lf.lift_insn(i, ALL)
            except LiftError as e:
                errors.append(str(e))
                continue
            body = []
            if args.annotate:
                body.append(f'  // {i.address:08X} {i.mnemonic} {i.op_str}')
            if lines:
                body.append('  ' + ' '.join(lines) if t is not None else '  { ' + ' '.join(lines) + ' }')
            body.append('  ' + (t or f'return {h(a + i.size)};'))
            units.append((a, 1, body))
    else:
        blocks = {}
        for a in lf.leaders:
            try:
                blocks[a] = lf.block_insns(a)
            except LiftError as e:
                errors.append(str(e))
        live_in, live_out = liveness(lf, blocks)
        for a, insns in blocks.items():
            try:
                body = lf.lift_block(a, insns, live_out[a] if lf.flag_opt else ALL)
            except LiftError as e:
                errors.append(str(e))
                continue
            units.append((a, len(insns), body))
        lf.stats['live_in_nonempty'] = sum(1 for v in live_in.values() if v)
        # per-block live-in flag sets (lift/test/flagopt.js checks the optimised lift against
        # the reference lift on every flag a successor needs)
        with open(os.path.join(args.out, 'livein.json'), 'w') as f:
            json.dump({h(a): ''.join(sorted(v)) for a, v in live_in.items()}, f)
    if errors:
        for e in errors[:50]:
            print('ERROR', e, file=sys.stderr)
        print(f'{len(errors)} lift errors', file=sys.stderr)
        sys.exit(1)

    # write files
    for f in os.listdir(args.out):
        if f.startswith('blocks-') and f.endswith('.js'):
            os.remove(os.path.join(args.out, f))
    nf = max(1, args.files)
    per = (len(units) + nf - 1) // nf
    files = []
    header = ("'use strict';\n// Generated by lift/lifter.py from the user's rct.exe. Do not commit.\n"
              "module.exports = function (rt, def) {\n"
              "const { r8, r16, r32, w8, w16, w32, P } = rt;\n"
              "const { mul8, mul16, mul32, imul8, imul16, imul32, div8, div16, div32, idiv8, idiv16, idiv32 } = rt;\n"
              "const { shl8, shl16, shl32, shr8, shr16, shr32, sar8, sar16, sar32, rol8, rol16, rol32, ror8, ror16, ror32,"
              " rcl8, rcl16, rcl32, rcr8, rcr16, rcr32, shrd32 } = rt;\n"
              "const { movs8, movs16, movs32, movs8Rep, movs16Rep, movs32Rep, stos8, stos16, stos32, stos8Rep, stos16Rep,"
              " stos32Rep, scas8Repne, scas8 } = rt;\n"
              "const { fld64, fstp64, fmul64, fdiv64, fsubr64, fcomp64, fnstsw, fldcw, cpuid, int3 } = rt;\n")
    ninsn = 0
    for k in range(nf):
        chunk = units[k * per:(k + 1) * per]
        if not chunk:
            break
        name = f'blocks-{k:02d}.js'
        with open(os.path.join(args.out, name), 'w') as f:
            f.write(header)
            for a, n, body in chunk:
                ninsn += n
                f.write(f'def({h(a)}, {n}, function b{a:X}(m) {{\n' + '\n'.join(body) + '\n});\n')
            f.write('};\n')
        files.append(name)
    # regions: blocks of the same code window in one function with a switch loop, so transitions
    # inside the window do not return to the dispatcher. The per-block functions above stay (the
    # instrumented loop and register capture use them).
    for f in os.listdir(args.out):
        if f.startswith('regions-') and f.endswith('.js'):
            os.remove(os.path.join(args.out, f))
    rfiles, nregions = [], 0
    if args.region_bits and not args.single:
        hookset = set(hooks)
        groups = []
        cur, key, cnt = [], None, 0
        for a, n, body in sorted(units):
            if a in hookset:
                continue
            k = a >> args.region_bits
            if cur and (k != key or cnt + n > args.region_max):
                groups.append(cur)
                cur, cnt = [], 0
            cur.append((a, n, body))
            key = k
            cnt += n
        if cur:
            groups.append(cur)
        nregions = len(groups)
        per_r = (len(groups) + nf - 1) // nf
        rheader = header.replace('module.exports = function (rt, def) {', 'module.exports = function (rt, defr) {')
        for k in range(nf):
            chunk = groups[k * per_r:(k + 1) * per_r]
            if not chunk:
                break
            name = f'regions-{k:02d}.js'
            with open(os.path.join(args.out, name), 'w') as f:
                f.write(rheader)
                for g in chunk:
                    starts = ', '.join(h(a) for a, _, _ in g)
                    # X (built by the loader): Int16Array over [first, last start], case index or -1.
                    # Dense case labels let V8 compile the switch to a jump table.
                    base, span = g[0][0], g[-1][0] - g[0][0] + 1
                    f.write(f'defr([{starts}], (X) => function r{base:X}(m, eip) {{\n  for (;;) {{\n'
                            f'    const k = eip - {h(base)};\n'
                            f'    switch (k >= 0 && k < {span} ? X[k] : -1) {{\n')
                    for ci, (a, n, body) in enumerate(g):
                        term = body[-1].strip()
                        assert term.startswith('return '), term
                        f.write(f'    case {ci}: {{ m._blk = {h(a)};\n' + '\n'.join(body[:-1]) +
                                f'\n  eip = {term[len("return "):].rstrip(";")} | 0; continue; }}\n')
                    f.write('    default: return eip;\n    }\n  }\n});\n')
                f.write('};\n')
            rfiles.append(name)
    man = {
        'lifter_version': LIFTER_VERSION, 'binary_md5': lf.md5, 'map': os.path.abspath(args.map),
        'regions': {'files': rfiles, 'count': nregions, 'bits': args.region_bits, 'max_insns': args.region_max},
        'mode': 'single' if args.single else 'blocks', 'flag_opt': lf.flag_opt,
        'nblocks': len(units), 'ninsns': ninsn, 'hooks': [h(a) for a in hooks], 'files': files,
        'map_blocks': len(cfg['blocks']), 'extra_leaders': [h(a) for a in sorted(set(hooks) - set(cfg['blocks']))],
        'derived_leaders': [h(a) for a in sorted(lf.derived)],
        'stats': lf.stats,
    }
    with open(os.path.join(args.out, 'manifest.json'), 'w') as f:
        json.dump(man, f, indent=1)
    print(json.dumps({k: man[k] for k in ('mode', 'flag_opt', 'nblocks', 'ninsns', 'extra_leaders')}),
          f'derived leaders: {len(lf.derived)}')


if __name__ == '__main__':
    main()
