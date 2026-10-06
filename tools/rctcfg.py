#!/usr/bin/env python3
"""Recursive-descent control-flow discovery for rct.exe (Stage 1 scoping, spike S1).

  .venv/bin/python tools/rctcfg.py [rct.exe] [outdir]      (default outdir: out/spikes/s1)

Writes cfg.json (function entries, basic-block starts, edges, unresolved indirect transfers,
per-section coverage) and report.md (measurements for scoping the mechanical lift). Neither
contains disassembly listings; both stay under out/ (git-ignored).

Discovery passes (each reported separately):
  A  entry point, game_do_command table (0x5F49A0), recursive descent through direct calls and
     jumps, `jmp [reg*4+table]` jump tables
  B  + immediate operands in decoded code that point at code (handler addresses passed in
     registers, e.g. window event tables `mov edx, 0x42B076`)
  C  + dwords in data sections that point into code and decode cleanly (function-pointer tables)
"""
import collections
import json
import os
import struct
import sys

import capstone
from capstone import x86 as X
import pefile

IB = 0x400000
SECTIONS = {'.text': (0x401000, 0x401000 + 0x1A1A6),
            'CODESEG': (0x41C000, 0x41C000 + 0x1CAC5D),
            'CodeSeg': (0x9B3000, 0x9B3000 + 0x9562)}
DATA = {'.rdata': (0x5E7000, 0x5E7000 + 0x1F46), '.data': (0x5E9000, 0x5E9000 + 0xAF74),
        'DATASEG': (0x5F4000, 0x9A161C), 'DataSeg': (0x9A2000, 0x9B2301)}
IAT = (0x5E7000, 0x5E7364)
CMD_TABLE, CMD_COUNT = 0x5F49A0, 49

FLAG_TEST = 0
FLAG_WRITE = 0
for n in dir(X):
    if n.startswith('X86_EFLAGS_TEST_'):
        FLAG_TEST |= getattr(X, n)
    elif n.startswith(('X86_EFLAGS_MODIFY_', 'X86_EFLAGS_SET_', 'X86_EFLAGS_RESET_', 'X86_EFLAGS_UNDEFINED_',
                       'X86_EFLAGS_PRIOR_')):
        FLAG_WRITE |= getattr(X, n)
# arithmetic flags only (CF PF AF ZF SF OF): the ones a callee can return a status in
ARITH_TEST = sum(getattr(X, f'X86_EFLAGS_TEST_{f}') for f in ('CF', 'PF', 'AF', 'ZF', 'SF', 'OF'))


def section_of(a):
    for n, (lo, hi) in SECTIONS.items():
        if lo <= a < hi:
            return n
    return None


def in_code(a):
    return section_of(a) is not None


class Image:
    def __init__(self, path):
        pe = pefile.PE(path)
        self.img = pe.get_memory_mapped_image()
        self.imports = {}
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                self.imports[i.address] = f"{e.dll.decode()}!{i.name.decode() if i.name else i.ordinal}"
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.cache = {}

    def u32(self, a):
        return struct.unpack_from('<I', self.img, a - IB)[0]

    def insn(self, a):
        if a in self.cache:
            return self.cache[a]
        sec = section_of(a)
        if sec is None:
            return None
        hi = SECTIONS[sec][1]
        code = bytes(self.img[a - IB:min(a - IB + 16, hi - IB)])
        r = next(self.md.disasm(code, a, 1), None)
        self.cache[a] = r
        return r


def mem_ops(i):
    return [o for o in i.operands if o.type == X.X86_OP_MEM]


def is_jcc(i):
    return i.group(capstone.CS_GRP_JUMP) and i.mnemonic not in ('jmp', 'ljmp')


# Instructions ring-3 Win32 game code has no use for. Seeing one in a heuristic seed's
# exploration means the seed decoded data as code.
IMPLAUSIBLE = {'in', 'out', 'insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd', 'hlt', 'cli', 'sti', 'int', 'int1',
               'into', 'iretd', 'iret', 'retf', 'bound', 'arpl', 'lds', 'les', 'lfs', 'lgs', 'lss', 'salc',
               'aaa', 'aas', 'daa', 'das', 'aam', 'aad', 'enter', 'ljmp', 'lcall', 'sldt', 'str',
               'sgdt', 'sidt', 'lgdt', 'lidt', 'clts', 'invd', 'wbinvd', 'rdmsr', 'wrmsr', 'icebp', 'ud1'}
SREGS = {'cs', 'ds', 'es', 'fs', 'gs', 'ss'}


def implausible(i):
    if i.mnemonic in IMPLAUSIBLE:
        return True
    if i.prefix[0] == 0xF0 or i.prefix[1] in (0x65, 0x36, 0x26) or i.mnemonic == 'int3':
        return True
    for o in i.operands:
        if o.type == X.X86_OP_REG:
            r = i.reg_name(o.reg)
            if r in SREGS:
                return True
            if r == 'esp' and i.mnemonic in ('inc', 'dec', 'mov', 'xchg', 'shl', 'shr', 'and', 'or', 'xor', 'adc', 'sbb') \
                    and (o.access & capstone.CS_AC_WRITE) and not (i.mnemonic == 'mov' and i.operands[1].type != X.X86_OP_IMM):
                return True
    return False


TABLE_MASK = set()   # bytes of probable pointer tables inside code sections (raw-byte scan)


def table_mask(im, minrun=3):
    m = set()
    for n, (lo, hi) in SECTIONS.items():
        a = (lo + 3) & ~3
        run = []
        while a + 4 <= hi:
            if in_code(im.u32(a)):
                run.append(a)
            else:
                if len(run) >= minrun:
                    for x in run:
                        m.update(range(x, x + 4))
                run = []
            a += 4
        if len(run) >= minrun:
            for x in run:
                m.update(range(x, x + 4))
    return m


def new_state():
    return dict(insn_at={}, owner={}, block_starts=set(), funcs=set(), edges=set(), unresolved=[],
                jumptables={}, overlaps=[], bad=[], implausible=[])


def discover(im, seeds, base=None, limit=None):
    """Recursive descent from `seeds`. With `base` (an accepted state), stops at instructions
    already in base and reports conflicts with it; the result holds only new code."""
    R = new_state()
    insn_at, owner = R['insn_at'], R['owner']
    G_ins = base['insn_at'] if base else {}
    G_own = base['owner'] if base else {}
    work = collections.deque()

    def add(a, func=False, src=None):
        if not in_code(a):
            R['bad'].append((a, f'target outside code from {src:#x}' if src else 'seed outside code'))
            return
        if func:
            R['funcs'].add(a)
        R['block_starts'].add(a)
        work.append(a)

    def read_table(tbl):
        tg = []
        for k in range(1024):
            slot = tbl + 4 * k
            if k and (slot in G_ins or slot in insn_at) and slot not in TABLE_MASK:
                break
            try:
                t = im.u32(slot)
            except struct.error:
                break
            if not in_code(t) or tbl <= t < slot + 4:
                break
            tg.append(t)
        return tg

    for a, f in seeds:
        add(a, f)
    seen = set()
    count = 0
    while work:
        a = work.popleft()
        if a in seen:
            continue
        seen.add(a)
        while True:
            if a in insn_at or a in G_ins:
                break
            if limit is not None and count >= limit:
                R['bad'].append((a, 'limit'))
                work.clear()
                break
            i = im.insn(a)
            if i is None:
                R['bad'].append((a, 'undecodable'))
                break
            for b in range(a, a + i.size):
                o = owner.get(b, G_own.get(b))
                if o is not None and o != a:
                    R['overlaps'].append((a, o))
                    break
            insn_at[a] = i
            count += 1
            if implausible(i) or (base is not None and any(b in TABLE_MASK for b in range(a, a + i.size))):
                R['implausible'].append(a)
            for b in range(a, a + i.size):
                owner.setdefault(b, a)
            nxt = a + i.size
            m = i.mnemonic
            if m.startswith('bnd ') or i.prefix[0] == 0xF2 and (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)):
                R['bad'].append((a, 'prefixed branch'))
            if m in ('ret', 'retf', 'iretd', 'hlt', 'ud2', 'int3'):
                break
            is_j = i.group(capstone.CS_GRP_JUMP)
            is_c = i.group(capstone.CS_GRP_CALL)
            if not (is_j or is_c):
                a = nxt
                continue
            op = i.operands[0]
            if op.type == X.X86_OP_IMM:
                t = op.imm & 0xFFFFFFFF
                R['edges'].add((a, t))
                add(t, func=is_c, src=a)
                if is_c or is_jcc(i):
                    R['edges'].add((a, nxt))
                    add(nxt, src=a)
                break
            if op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and \
                    IAT[0] <= (op.mem.disp & 0xFFFFFFFF) < IAT[1]:
                if is_c:
                    R['edges'].add((a, nxt))
                    add(nxt, src=a)
                break   # import call / import thunk
            if op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index != 0 and op.mem.scale == 4:
                tbl = op.mem.disp & 0xFFFFFFFF
                tg = read_table(tbl)
                R['jumptables'][a] = (tbl, tg)
                if in_code(tbl):
                    for b in range(tbl, tbl + 4 * len(tg)):
                        owner.setdefault(b, -tbl)
                for t in tg:
                    R['edges'].add((a, t))
                    add(t, func=is_c, src=a)
                if not tg:
                    R['unresolved'].append((a, 'table-empty', f'{i.mnemonic} {i.op_str}'))
            else:
                R['unresolved'].append((a, ('call' if is_c else 'jmp') + ' reg/mem', f'{i.mnemonic} {i.op_str}'))
            if is_c:
                R['edges'].add((a, nxt))
                add(nxt, src=a)
            break
    return R


def merge(G, R):
    G['insn_at'].update(R['insn_at'])
    for b, o in R['owner'].items():
        G['owner'].setdefault(b, o)
    for k in ('block_starts', 'funcs', 'edges'):
        G[k] |= R[k]
    for k in ('unresolved', 'overlaps', 'bad', 'implausible'):
        G[k] += R[k]
    G['jumptables'].update(R['jumptables'])


def clean(R):
    return not R['overlaps'] and not R['implausible'] and not any(r != 'limit' for _, r in R['bad'])


def aligned_with_neighbours(im, G, a, window=256):
    """Linear decode from the end of the nearest preceding accepted instruction (or table byte)
    must land exactly on `a`. False if it steps over `a` (a mid-instruction seed)."""
    own = G['owner']
    b = a - 1
    while b >= a - window and b not in own and b not in TABLE_MASK:
        b -= 1
    if b < a - window:
        return True                   # nothing known nearby: inconclusive
    if b in TABLE_MASK:
        p = b + 1
    else:
        s0 = own[b]
        p = (s0 + G['insn_at'][s0].size) if s0 > 0 else b + 1
    while p < a:
        i = im.insn(p)
        if i is None or implausible(i):
            return True               # inconclusive
        p += i.size
    return p == a


def gated(im, G, seeds, stats, ctx, limit=20000):
    """Try each heuristic seed; accept it only if its exploration is clean against G.
    ctx: {'direct': direct branch targets, 'group': insn start -> seed (heuristic) or 'T',
          'groups': seed -> [insn starts], 'conflicts': [(rejected seed, accepted seed)], 'removed': {seed: reason}}"""
    for a, f in seeds:
        if a in G['insn_at']:
            if f:
                G['funcs'].add(a)
            G['block_starts'].add(a)
            stats['known'] += 1
            continue
        if a in G['owner']:
            stats['inside'] += 1
            continue
        if (a & 0xFFFF) == 0 and a not in ctx['direct']:
            # 0x00XX0000 is a common small-integer pattern in game data; real 64 KiB-aligned
            # entries in this binary are reached by direct branches
            stats['aligned64k'] += 1
            ctx['removed'][a] = '64 KiB aligned, not a direct branch target'
            continue
        if not aligned_with_neighbours(im, G, a):
            stats['misaligned'] += 1
            continue
        R = discover(im, [(a, f)], G, limit)
        if clean(R):
            merge(G, R)
            for x in R['insn_at']:
                ctx['group'][x] = a
            ctx['groups'][a] = list(R['insn_at'])
            stats['accepted'] += 1
        else:
            stats['rejected'] += 1
            if R['overlaps'] and not R['implausible'] and not any(r != 'limit' for _, r in R['bad']):
                for _, o in R['overlaps']:
                    owner_seed = ctx['group'].get(o) if o > 0 else None
                    if owner_seed is not None and owner_seed != 'T':
                        ctx['conflicts'].append((a, owner_seed))


def direct_targets(G):
    out = set()
    for a, i in G['insn_at'].items():
        if (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)) and i.operands and \
                i.operands[0].type == X.X86_OP_IMM:
            out.add(i.operands[0].imm & 0xFFFFFFFF)
    return out


def load_dyn(path):
    if not os.path.exists(path):
        return []
    d = open(path, 'rb').read()
    return list(struct.unpack('<%dI' % (len(d) // 4), d[:len(d) // 4 * 4]))


def split_blocks(res):
    """Basic-block leaders: block_starts plus instruction after every control transfer."""
    leaders = set(a for a in res['block_starts'] if a in res['insn_at'])
    for a, i in res['insn_at'].items():
        if i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL) or i.mnemonic in ('ret', 'retf'):
            n = a + i.size
            if n in res['insn_at']:
                leaders.add(n)
    return sorted(leaders)


def imm_code_refs(res):
    out = set()
    for a, i in res['insn_at'].items():
        if i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL):
            continue
        for o in i.operands:
            if o.type == X.X86_OP_IMM:
                v = o.imm & 0xFFFFFFFF
                if in_code(v):
                    out.add((v, a))
    return out


def data_code_ptrs(im):
    out = []
    for n, (lo, hi) in DATA.items():
        if n == '.rdata':
            lo = IAT[1]   # skip IAT
        for a in range(lo, hi - 3, 1 if False else 4):
            v = im.u32(a)
            if in_code(v):
                out.append((a, v, n))
    return out


def embedded_tables(im, R):
    """(slot, target) for aligned dword runs (>= 3) inside code sections not covered by decoded code."""
    covered = set()
    for a, i in R['insn_at'].items():
        covered.update(range(a, a + i.size))
    for _, (t, tg) in R['jumptables'].items():
        covered.update(range(t, t + 4 * len(tg)))
    out = set()
    for n, (lo, hi) in SECTIONS.items():
        a = (lo + 3) & ~3
        run = []
        while a + 4 <= hi:
            v = im.u32(a)
            if not any(b in covered for b in range(a, a + 4)) and in_code(v):
                run.append((a, v))
            else:
                if len(run) >= 3:
                    out.update(run)
                run = []
            a += 4
        if len(run) >= 3:
            out.update(run)
    return out


def decodes_cleanly(im, a, n=6):
    """Heuristic validation of a data pointer as code: n instructions decode, no bad opcodes."""
    for _ in range(n):
        i = im.insn(a)
        if i is None or i.mnemonic in ('(bad)',):
            return False
        if i.mnemonic in ('ret', 'jmp'):
            return True
        a += i.size
    return True


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else 'game/cd/English/rct.exe'
    out = sys.argv[2] if len(sys.argv) > 2 else 'out/spikes/s1'
    os.makedirs(out, exist_ok=True)
    im = Image(exe)

    entry = 0x412E80
    cmd = [im.u32(CMD_TABLE + 4 * k) for k in range(CMD_COUNT)]
    TABLE_MASK.update(table_mask(im))
    dyn_path = os.path.join(os.path.dirname(out.rstrip('/')), 'istep_addrs.bin')
    dyn = load_dyn(dyn_path)
    trusted_seeds = [(entry, True)] + [(c, True) for c in cmd] + [(d, False) for d in dyn if in_code(d)]
    T = discover(im, trusted_seeds)                                        # pass A + dynamic: trusted
    G = new_state()
    merge(G, T)
    snap = {'A': (len(G['funcs']), len(G['insn_at']))}
    gate = {k: collections.Counter() for k in 'BCD'}
    ctx = {'direct': direct_targets(G), 'group': {x: 'T' for x in G['insn_at']}, 'groups': {},
           'conflicts': [], 'removed': {}}

    refs = set()
    dptr = data_code_ptrs(im)
    embedded = set()
    for rnd in range(40):
        before = len(G['insn_at'])
        refs |= imm_code_refs(G)
        embedded |= embedded_tables(im, G)
        ctx['direct'] |= direct_targets(G)
        # Candidates from all heuristic sources, most-referenced first: a true entry point is
        # usually referenced from several slots, a mis-decode usually from one. Ties by source
        # priority (immediates in decoded code > embedded tables > data-section dwords).
        cand = collections.defaultdict(lambda: [0, 9, None])
        for v, _ in refs:
            c = cand[v]; c[0] += 1; c[1] = min(c[1], 0); c[2] = c[2] or 'B'
        for _, v in embedded:
            c = cand[v]; c[0] += 1; c[1] = min(c[1], 1); c[2] = c[2] or 'D'
        for _, v, _ in dptr:
            c = cand[v]; c[0] += 1; c[1] = min(c[1], 2); c[2] = c[2] or 'C'
        order = sorted(cand.items(), key=lambda kv: (-kv[1][0], kv[1][1], kv[0]))
        for v, (n, pri, src) in order:
            gated(im, G, [(v, False)], gate['BDC'[pri]], ctx)
        if len(G['insn_at']) == before:
            break
    snap['B'] = snap['C'] = snap['D'] = (len(G['funcs']), len(G['insn_at']))

    # Order-independent conflict check: a heuristic group that another heuristic seed's clean
    # decode overlapped is dropped, whichever was accepted first (trusted code is never dropped).
    accepted = list(ctx['groups'])
    dropped = {}
    for rej, acc in ctx['conflicts']:
        if acc in ctx['groups'] and acc not in dropped:
            dropped[acc] = f'overlapped by heuristic seed {rej:#x}'
    keep = [s_ for s_ in accepted if s_ not in dropped]
    pre_v2 = (len(G['insn_at']), len(split_blocks(G)))
    # rebuild from trusted + surviving heuristic seeds; drop seeds until no overlap remains
    for _ in range(20):
        F = discover(im, trusted_seeds + [(s_, False) for s_ in keep])
        if not F['overlaps']:
            break
        bad_starts = set()
        for x, o in F['overlaps']:
            bad_starts.update((x, o))
        # attribute to the heuristic seeds whose standalone decode contains the conflicting starts
        culprits = set()
        for s_ in keep:
            if any(b_ in bad_starts for b_ in ctx['groups'].get(s_, [])) or s_ in bad_starts:
                culprits.add(s_)
        if not culprits:
            break
        for c_ in culprits:
            dropped[c_] = 'overlap in rebuilt map'
        keep = [s_ for s_ in keep if s_ not in culprits]
    G = F
    G['funcs'] |= set(a_ for a_, f_ in trusted_seeds if f_)
    # The other side of each dropped conflict was rejected only because the dropped group was
    # there first. Re-gate those seeds once against the rebuilt map (same gate, 64 KiB rule).
    recovered = []
    retry = sorted(set(r for r, a_ in ctx['conflicts'] if a_ in dropped and r not in dropped))
    rctx = {'direct': direct_targets(G), 'group': {x: 'T' for x in G['insn_at']}, 'groups': {},
            'conflicts': [], 'removed': {}}
    rstats = collections.Counter()
    for r in retry:
        before = len(rctx['groups'])
        gated(im, G, [(r, False)], rstats, rctx)
        if len(rctx['groups']) > before:
            recovered.append(r)
    if recovered:
        F = discover(im, trusted_seeds + [(s_, False) for s_ in keep + recovered])
        if F['overlaps']:
            recovered = []          # be conservative: keep the map overlap-free
        else:
            G = F
            G['funcs'] |= set(a_ for a_, f_ in trusted_seeds if f_)
    v2 = {'pre': pre_v2, 'dropped': dropped, 'removed': ctx['removed'], 'trusted': T, 'dyn': dyn,
          'dyn_path': dyn_path, 'kept_seeds': keep, 'retry': retry, 'recovered': recovered,
          'retry_stats': dict(rstats)}

    blocks = split_blocks(G)
    report = analyse(im, G, blocks, snap, gate, refs, dptr, cmd, embedded)

    tblocks = split_blocks(T)
    tset = set(tblocks)
    prov = ['A/dyn' if b_ in tset else 'heuristic' for b_ in blocks]
    cfg = {
        'binary_md5': '59e88bbcf3a6db7ea81c648a4afba935',
        'functions': sorted(G['funcs']),
        'blocks': blocks,
        'block_provenance': prov,
        'blocks_trusted': tblocks,
        'instructions': len(G['insn_at']),
        'instruction_starts': sorted(G['insn_at']),
        'edges': sorted(G['edges']),
        'unresolved': [{'addr': a, 'kind': k, 'insn': t} for a, k, t in sorted(set(G['unresolved']))],
        'jumptables': {str(a): {'table': t, 'targets': tg} for a, (t, tg) in sorted(G['jumptables'].items())},
        'game_commands': cmd,
        'passes': {'A': 'entry + game_do_command table (trusted)', 'B': '+ code-pointer immediates (gated)',
                   'C': '+ data-section dwords pointing at code (gated)',
                   'D': '+ pointer tables embedded in code sections (gated)'},
        'pass_counts': snap,
        'gate_stats': {k: dict(v) for k, v in gate.items()},
        'coverage': report['coverage'],
    }
    with open(os.path.join(out, 'cfg.json'), 'w') as f:
        json.dump(cfg, f)
    for name, bl in (('blocks-all.bin', blocks), ('blocks-trusted.bin', tblocks)):
        with open(os.path.join(out, name), 'wb') as f:
            f.write(struct.pack('<%dI' % len(bl), *bl))
    text = report['text'] + v2_section(im, G, blocks, tblocks, v2, out)
    with open(os.path.join(out, 'report.md'), 'w') as f:
        f.write(text)
    print(text)


def analyse(im, R, blocks, snap, gate, refs, dptr, cmd, embedded=()):
    ins = R['insn_at']
    L = ['# Spike S1: static code discovery for rct.exe', '']
    # ---------------- 1. counts and coverage
    cov = {}
    tables = {t: len(tg) for _, (t, tg) in R['jumptables'].items()}
    for n, (lo, hi) in SECTIONS.items():
        code = bytearray(hi - lo)
        for a, i in ins.items():
            if lo <= a < hi:
                for b in range(a, min(a + i.size, hi)):
                    code[b - lo] = 1
        tb = bytearray(hi - lo)
        for t, k in tables.items():
            for b in range(t, t + 4 * k):
                if lo <= b < hi:
                    tb[b - lo] = 1
        dec, tbl = sum(code), sum(tb)
        both = sum(1 for k in range(hi - lo) if code[k] and tb[k])
        cov[n] = {'bytes': hi - lo, 'decoded': dec, 'jumptable_bytes': tbl, 'table_and_code_overlap': both,
                  'pct_decoded': round(100.0 * dec / (hi - lo), 2),
                  'pct_accounted': round(100.0 * (dec + tbl - both) / (hi - lo), 2)}
    L.append('## 1. Counts')
    L.append('')
    L.append('Heuristic seeds (B, C, D) are gated: a seed is accepted only if its own recursive descent')
    L.append('decodes cleanly, reaches no target outside code, overlaps no accepted instruction, and contains')
    L.append('no instruction ring-3 game code has no use for (in/out, hlt, cli/sti, int, retf/iretd, enter,')
    L.append('segment-register moves, BCD adjust, bound, lds/les, lock, esp arithmetic other than push/pop/add/sub/lea),')
    L.append(f'and decodes nothing inside a probable pointer table (raw aligned runs of >= 3 code pointers: {len(TABLE_MASK)} bytes).')
    L.append('B-D candidates are pooled each round and gated most-referenced first, iterating to a fixed point;')
    L.append('the B/C/D rows show the final totals and how many candidates each source contributed.')
    L.append('')
    L.append('| pass | seeds | functions | instructions | gate (accepted / rejected / already known / inside insn / misaligned) |')
    L.append('|---|---|---|---|---|')
    for k, desc in (('A', 'entry + game_do_command table, recursive descent, jump tables'),
                    ('B', '+ immediates pointing at code (handlers passed in registers)'),
                    ('C', '+ data-section dwords pointing at code'),
                    ('D', '+ pointer tables embedded in code sections (runs of >= 3 aligned code pointers)')):
        g = gate.get(k, {})
        gs = (f"{g.get('accepted', 0)} / {g.get('rejected', 0)} / {g.get('known', 0)} / {g.get('inside', 0)} / "
              f"{g.get('misaligned', 0)}") if k in gate else 'trusted'
        L.append(f"| {k} | {desc} | {snap[k][0]} | {snap[k][1]} | {gs} |")
    L.append('')
    L.append(f'Embedded code-section pointer slots used as seeds in pass D: {len(embedded)}.')
    L.append(f"Final (pass D): **{len(R['funcs'])} call targets (functions)**, **{len(blocks)} basic blocks**, "
             f"**{len(ins)} instructions**, {len(R['edges'])} edges, {len(R['jumptables'])} jump/call tables "
             f"({sum(len(tg) for _, tg in R['jumptables'].values())} entries).")
    L.append('')
    L.append('| section | bytes | decoded as code | in jump/pointer tables | both | % code | % code or table |')
    L.append('|---|---|---|---|---|---|---|')
    for n, c in cov.items():
        L.append(f"| {n} | {c['bytes']} | {c['decoded']} | {c['jumptable_bytes']} | {c['table_and_code_overlap']} | "
                 f"{c['pct_decoded']} | {c['pct_accounted']} |")
    L.append('')
    # gaps
    L.append('### Undecoded gaps')
    L.append('')
    for n, (lo, hi) in SECTIONS.items():
        covered = bytearray(hi - lo)
        for a, i in ins.items():
            if lo <= a < hi:
                for b in range(a, min(a + i.size, hi)):
                    covered[b - lo] = 1
        for _, (t, tg) in R['jumptables'].items():
            for b in range(t, t + 4 * len(tg)):
                if lo <= b < hi:
                    covered[b - lo] = 2
        gaps = []
        s = None
        for k in range(hi - lo + 1):
            c = covered[k] if k < hi - lo else 1
            if c == 0 and s is None:
                s = k
            elif c != 0 and s is not None:
                gaps.append((lo + s, k - s))
                s = None
        kinds = collections.Counter()
        kbytes = collections.Counter()
        big = []
        for g, ln in gaps:
            raw = bytes(im.img[g - IB:g - IB + ln])
            if all(b in (0x90, 0xCC, 0x00) for b in raw):
                kd = 'padding (00/90/CC)'
            else:
                # does it decode as plausible code ending in ret/jmp?
                a = g
                ok = 0
                while a < g + ln:
                    i = im.insn(a)
                    if i is None:
                        break
                    ok += 1
                    a += i.size
                kd = 'decodable (unreached code or data)' if a >= g + ln and ok > 2 else 'data-like'
                if ln >= 64:
                    big.append((g, ln, kd))
            kinds[kd] += 1
            kbytes[kd] += ln
        L.append(f"- **{n}**: {len(gaps)} gaps, " + ', '.join(f'{k}: {kinds[k]} gaps / {kbytes[k]} bytes' for k in kinds))
        for g, ln, kd in sorted(big, key=lambda x: -x[1])[:12]:
            L.append(f"  - {g:#x} +{ln} ({kd})")
    L.append('')
    # unresolved
    un = sorted(set(R['unresolved']))
    L.append(f'### Unresolved indirect transfers: {len(un)}')
    L.append('')
    byk = collections.Counter((k, t.split()[0]) for _, k, t in un)
    for (k, mn), c in byk.most_common():
        L.append(f'- {k} ({mn}): {c}')
    L.append('')
    L.append('| addr | instruction | guess |')
    L.append('|---|---|---|')
    for a, k, t in un:
        L.append(f'| {a:#x} | `{t}` | {guess_indirect(t)} |')
    L.append('')
    imp = sorted(set(R['implausible']))
    L.append(f'Implausible instructions remaining in the map (only possible from trusted pass-A descent): {len(imp)}' +
             (': ' + ', '.join(f"{a:#x} `{ins[a].mnemonic} {ins[a].op_str}`" for a in imp[:40]) if imp else '.'))
    if R['overlaps']:
        L.append(f"Overlapping instruction starts: {len(R['overlaps'])}: " +
                 ', '.join(f'{a:#x} inside {b:#x}' for a, b in R['overlaps'][:30]))
    else:
        L.append('Overlapping instruction starts: none.')
    badc = collections.Counter(r.split(' from')[0] for _, r in R['bad'])
    L.append(f"Bad targets: {dict(badc)}" + (' e.g. ' + ', '.join(f'{a:#x} ({r})' for a, r in R['bad'][:10]) if R['bad'] else ''))
    L.append('')

    # ---------------- 2. instruction census
    L.append('## 2. Instruction census')
    L.append('')
    mn = collections.Counter(i.mnemonic for i in ins.values())
    L.append(f'{len(mn)} distinct mnemonics. Top 60:')
    L.append('')
    L.append(', '.join(f'{m} {c}' for m, c in mn.most_common(60)))
    L.append('')
    L.append('All mnemonics (by count): ' + ', '.join(f'{m} {c}' for m, c in sorted(mn.items(), key=lambda x: -x[1])[60:]))
    L.append('')

    def where(pred):
        hits = [a for a, i in ins.items() if pred(i)]
        secs = collections.Counter(section_of(a) for a in hits)
        return hits, secs

    fpu, s = where(lambda i: i.group(X.X86_GRP_FPU) or i.mnemonic.startswith('f') and i.mnemonic not in ('fwait',) and i.mnemonic[:2] in ('fl', 'fs', 'fi', 'fa', 'fm', 'fd', 'fc', 'fn', 'fx', 'fr', 'fp', 'fy', 'fb', 'ft', 'fu', 'f2', 'ff'))
    L.append(f'- **x87 FPU**: {len(fpu)} instructions; by section {dict(s)}; mnemonics ' +
             str(collections.Counter(ins[a].mnemonic for a in fpu).most_common(25)) +
             (f"; CODESEG sites (first 20): {', '.join(hex(a) for a in sorted(x for x in fpu if section_of(x) != '.text')[:20])}" if any(section_of(x) != '.text' for x in fpu) else ''))
    mmx, s = where(lambda i: i.group(X.X86_GRP_MMX) or i.group(X.X86_GRP_SSE1) or i.group(X.X86_GRP_SSE2) or i.mnemonic.startswith(('p', 'movq', 'movd', 'emms')) and i.mnemonic not in ('push', 'pop', 'pushal', 'popal', 'pushfd', 'popfd', 'pushf', 'popf', 'pause', 'pushfw', 'popfw', 'pushaw', 'popaw'))
    L.append(f'- **MMX/SSE**: {len(mmx)}; by section {dict(s)}; ' + str(collections.Counter(ins[a].mnemonic for a in mmx).most_common(10)))
    rep, s = where(lambda i: i.prefix[0] in (0xF2, 0xF3))
    L.append(f'- **rep/repne-prefixed**: {len(rep)}; by section {dict(s)}; ' +
             str(collections.Counter((('repne ' if ins[a].prefix[0] == 0xF2 else 'rep ') + ins[a].mnemonic) for a in rep).most_common(15)))
    strops, s = where(lambda i: i.mnemonic.rstrip('bwd') in ('movs', 'stos', 'lods', 'scas', 'cmps') or i.mnemonic in ('movsb', 'movsw', 'movsd', 'stosb', 'stosw', 'stosd', 'lodsb', 'lodsw', 'lodsd', 'scasb', 'scasw', 'scasd', 'cmpsb', 'cmpsw', 'cmpsd'))
    L.append(f'- **string ops (any)**: {len(strops)}; by section {dict(s)}')
    segov, s = where(lambda i: i.prefix[1] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65))
    L.append(f'- **segment override prefixes**: {len(segov)}; by section {dict(s)}; ' +
             str(collections.Counter({0x26: 'es', 0x2E: 'cs', 0x36: 'ss', 0x3E: 'ds', 0x64: 'fs', 0x65: 'gs'}[ins[a].prefix[1]] for a in segov)) +
             (f"; non-.text: {', '.join(hex(a) for a in segov if section_of(a) != '.text')[:400]}" if any(section_of(a) != '.text' for a in segov) else ''))
    segmov, s = where(lambda i: any(o.type == X.X86_OP_REG and i.reg_name(o.reg) in ('cs', 'ds', 'es', 'fs', 'gs', 'ss') for o in i.operands))
    L.append(f'- **segment registers as operands** (mov/push/pop sreg): {len(segmov)}; by section {dict(s)}; ' +
             ', '.join(f'{a:#x} {ins[a].mnemonic} {ins[a].op_str}' for a in sorted(segmov)[:15]))
    odd = {'int', 'int3', 'into', 'in', 'out', 'insb', 'insd', 'outsb', 'outsd', 'cli', 'sti', 'rdtsc', 'cpuid',
           'bound', 'xlatb', 'aam', 'aad', 'daa', 'das', 'aaa', 'aas', 'hlt', 'lahf', 'sahf', 'cld', 'std',
           'enter', 'leave', 'lds', 'les', 'lfs', 'lgs', 'lss', 'arpl', 'salc', 'cmc', 'pushal', 'popal',
           'pushfd', 'popfd', 'bswap', 'cmpxchg', 'xadd', 'wait', 'sgdt', 'sidt', 'smsw', 'str', 'sldt'}
    oddc = collections.Counter()
    oddsites = collections.defaultdict(list)
    for a, i in ins.items():
        if i.mnemonic in odd:
            oddc[(i.mnemonic, section_of(a))] += 1
            oddsites[i.mnemonic].append(a)
    lock = [a for a, i in ins.items() if i.prefix[0] == 0xF0]
    L.append(f'- **unusual/privileged**: ' + ', '.join(f'{m}@{s} {c}' for (m, s), c in sorted(oddc.items())) +
             f'; lock-prefixed {len(lock)}')
    for m in ('int', 'in', 'out', 'rdtsc', 'cpuid', 'bound', 'xlatb', 'aam', 'aad', 'daa', 'das', 'lahf', 'sahf',
              'cli', 'sti', 'std', 'lds', 'les', 'lfs', 'salc', 'cmpxchg', 'bswap'):
        if oddsites.get(m):
            L.append(f'  - {m}: ' + ', '.join(hex(a) for a in sorted(oddsites[m])[:12]))
    pre66 = sum(1 for i in ins.values() if i.prefix[2] == 0x66)
    pre66c = sum(1 for a, i in ins.items() if i.prefix[2] == 0x66 and section_of(a) == 'CODESEG')
    codeseg_n = sum(1 for a in ins if section_of(a) == 'CODESEG')
    L.append(f'- **0x66 operand-size prefix**: {pre66} instructions ({pre66c} of {codeseg_n} in CODESEG = '
             f'{100.0 * pre66c / max(1, codeseg_n):.1f}%)')
    # partial registers
    part = sum(1 for a, i in ins.items() if section_of(a) == 'CODESEG' and any(
        o.type == X.X86_OP_REG and i.reg_name(o.reg) in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh') for o in i.operands))
    L.append(f'- **8-bit register operands in CODESEG**: {part} instructions ({100.0 * part / max(1, codeseg_n):.1f}%); '
             f'ah/bh/ch/dh high-byte use: ' + str(sum(1 for a, i in ins.items() if section_of(a) == 'CODESEG' and any(
                 o.type == X.X86_OP_REG and i.reg_name(o.reg) in ('ah', 'bh', 'ch', 'dh') for o in i.operands))))
    # self-referential memory operands
    smc_w, smc_r = [], []
    for a, i in ins.items():
        for o in i.operands:
            if o.type == X.X86_OP_MEM and o.mem.base == 0 and o.mem.index == 0 and in_code(o.mem.disp & 0xFFFFFFFF) \
                    and not (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)):
                (smc_w if o.access & capstone.CS_AC_WRITE else smc_r).append((a, o.mem.disp & 0xFFFFFFFF))
    L.append(f'- **absolute memory operands inside code sections** (candidate self-modifying code / data in code): '
             f'{len(smc_w)} writes, {len(smc_r)} reads')
    tgt = collections.Counter(section_of(t) for _, t in smc_w)
    L.append(f'  - writes by target section {dict(tgt)}; writer section ' + str(dict(collections.Counter(section_of(a) for a, _ in smc_w))))
    L.append('  - writes (writer -> target): ' + ', '.join(f'{a:#x}->{t:#x}' for a, t in sorted(smc_w)[:80]))
    tw = sorted(set(t for _, t in smc_w))
    L.append(f'  - distinct written code addresses: {len(tw)}; are they instruction bytes of decoded code? ' +
             str(collections.Counter('inside-insn' if (R['owner'].get(t, None) or 0) > 0 else 'not-decoded' for t in tw)))
    L.append('  - reads (first 40): ' + ', '.join(f'{a:#x}->{t:#x}' for a, t in sorted(smc_r)[:40]))
    # immediates that point into CodeSeg used as data pointers (mov edi, imm; stos ...)
    imm_cs = sorted(set((a, v) for v, a in refs if section_of(v) == 'CodeSeg' and section_of(a) != 'CodeSeg'))
    L.append(f'- immediates pointing into CodeSeg from other sections: {len(imm_cs)}')
    L.append('')

    # ---------------- 3. flags as output
    L.append('## 3. Flags as function outputs')
    L.append('')
    sites = []
    for a, i in ins.items():
        if not i.group(capstone.CS_GRP_CALL):
            continue
        op = i.operands[0]
        if op.type != X.X86_OP_IMM:
            continue
        callee = op.imm & 0xFFFFFFFF
        b = a + i.size
        reads = None
        for _ in range(12):
            j = ins.get(b) or im.insn(b)
            if j is None:
                break
            if j.eflags & ARITH_TEST:
                reads = j
                break
            if j.eflags & FLAG_WRITE and not (j.eflags & FLAG_TEST):
                break
            if j.group(capstone.CS_GRP_CALL) or j.mnemonic in ('ret', 'jmp'):
                break
            b += j.size
        if reads is not None:
            sites.append((a, callee, reads.mnemonic, section_of(a)))
    callees = collections.Counter(c for _, c, _, _ in sites)
    allcalls = sum(1 for a, i in ins.items() if i.group(capstone.CS_GRP_CALL) and i.operands[0].type == X.X86_OP_IMM)
    L.append(f'Direct call sites: {allcalls}. Call sites whose caller reads arithmetic flags after the call before '
             f'writing them: **{len(sites)}** ({dict(collections.Counter(s for *_, s in sites))}), '
             f'**{len(callees)} distinct callees**. Reading instruction: ' +
             str(collections.Counter(m for _, _, m, _ in sites).most_common(12)))
    L.append('')
    L.append('Top callees by flag-reading call sites: ' + ', '.join(f'{c:#x}({n})' for c, n in callees.most_common(30)))
    L.append('')
    # callee exits: last instruction before each ret that writes arithmetic flags
    exit_kinds = collections.Counter()
    esc_funcs = set()
    for a, i in ins.items():
        if i.mnemonic != 'ret':
            continue
        # walk back linearly (within decoded code) up to 6 instructions
        prev = [p for p in range(a - 15, a) if p in ins and p + ins[p].size == a]
        if not prev:
            continue
        p = ins[prev[0]]
        exit_kinds[p.mnemonic] += 1
    L.append('Instruction immediately before `ret` (all rets): ' + str(exit_kinds.most_common(20)))
    flag_setters = {'cmp', 'test', 'stc', 'clc', 'cmc', 'or', 'and', 'sub', 'add', 'xor', 'bt', 'btr', 'bts', 'dec', 'inc', 'neg', 'shr', 'shl', 'sar', 'ror', 'rol', 'sbb', 'adc'}
    L.append(f"rets directly preceded by a flag-setting instruction: {sum(c for m, c in exit_kinds.items() if m in flag_setters)} "
             f"(stc {exit_kinds.get('stc', 0)}, clc {exit_kinds.get('clc', 0)}, cmp {exit_kinds.get('cmp', 0)}, test {exit_kinds.get('test', 0)})")
    L.append('')

    # ---------------- 4. CODESEG -> .text boundary
    L.append('## 4. Calls from CODESEG/CodeSeg into .text (C runtime / OS glue)')
    L.append('')
    glue = collections.Counter()
    for a, i in ins.items():
        if section_of(a) in ('CODESEG', 'CodeSeg') and i.group(capstone.CS_GRP_CALL) and i.operands[0].type == X.X86_OP_IMM:
            t = i.operands[0].imm & 0xFFFFFFFF
            if section_of(t) == '.text':
                glue[t] += 1
    L.append(f'{len(glue)} distinct .text functions, {sum(glue.values())} call sites. Each with the imports it reaches '
             '(direct IAT calls/jumps in its first 40 instructions, following unconditional jumps):')
    L.append('')
    for t, c in sorted(glue.items(), key=lambda x: (-x[1], x[0])):
        L.append(f'- {t:#x} x{c}: ' + ', '.join(sorted(imports_reached(im, ins, t))))
    # .text -> CODESEG calls (callbacks into game)
    back = collections.Counter()
    for a, i in ins.items():
        if section_of(a) == '.text' and i.group(capstone.CS_GRP_CALL) and i.operands[0].type == X.X86_OP_IMM:
            t = i.operands[0].imm & 0xFFFFFFFF
            if section_of(t) in ('CODESEG', 'CodeSeg'):
                back[t] += 1
    L.append('')
    L.append(f'.text -> CODESEG/CodeSeg direct calls: {sum(back.values())} sites to {len(back)} targets: ' +
             ', '.join(f'{t:#x}' for t in sorted(back)))
    cs_calls = collections.Counter()
    for a, i in ins.items():
        if section_of(a) == 'CODESEG' and i.group(capstone.CS_GRP_CALL) and i.operands[0].type == X.X86_OP_IMM:
            t = i.operands[0].imm & 0xFFFFFFFF
            if section_of(t) == 'CodeSeg':
                cs_calls[t] += 1
    L.append('')
    L.append(f'CODESEG -> CodeSeg direct calls: {sum(cs_calls.values())} sites to {len(cs_calls)} targets.')
    iat_cs = sum(1 for a, i in ins.items() if section_of(a) in ('CODESEG', 'CodeSeg') and any(
        o.type == X.X86_OP_MEM and o.mem.base == 0 and o.mem.index == 0 and IAT[0] <= (o.mem.disp & 0xFFFFFFFF) < IAT[1] for o in i.operands))
    L.append(f'IAT references from CODESEG/CodeSeg (direct OS calls bypassing .text): {iat_cs}')
    L.append('')

    # ---------------- 5. code reached via data
    L.append('## 5. Code reached through data')
    L.append('')
    bysec = collections.Counter(n for _, _, n in dptr)
    L.append(f'Aligned dwords in data sections whose value lies in a code section: {len(dptr)} {dict(bysec)}.')
    lands = collections.Counter('instruction start' if v in ins else ('inside an instruction' if v in R['owner'] else 'undecoded')
                                for _, v, _ in dptr)
    L.append(f'Where they land in the final code map: {dict(lands)}.')
    real = [(a, v, n) for a, v, n in dptr if v in ins]
    L.append(f"Pointers that hit instruction starts, by section: {dict(collections.Counter(n for _, _, n in real))}; "
             f"distinct targets {len(set(v for _, v, _ in real))}.")
    L.append('Sample (data addr -> target): ' + ', '.join(f'{a:#x}->{v:#x}' for a, v, _ in real[:30]))
    L.append(f'Embedded pointer slots inside code sections (pass D candidates): {len(embedded)}; '
             f"their targets at instruction starts: {sum(1 for _, v in embedded if v in ins)}.")
    imm_sec = collections.Counter(section_of(a) for v, a in refs)
    L.append(f'Code-pointer immediates in code: {len(refs)} (by referencing section {dict(imm_sec)}).')
    L.append('')

    # ---------------- 6. lift complications
    L.append('## 6. Lift complications')
    L.append('')
    espw = [(a, f'{i.mnemonic} {i.op_str}') for a, i in ins.items()
            if any(o.type == X.X86_OP_REG and i.reg_name(o.reg) == 'esp' and (o.access & capstone.CS_AC_WRITE) for o in i.operands)
            and i.mnemonic not in ('push', 'pop', 'call', 'ret', 'pushal', 'popal', 'pushfd', 'popfd', 'leave', 'enter')
            and not (i.mnemonic in ('add', 'sub') and i.operands[1].type == X.X86_OP_IMM)]
    L.append(f'- esp written other than push/pop/add/sub imm: {len(espw)}: ' + ', '.join(f'{a:#x} `{t}`' for a, t in sorted(espw)[:40]))
    pushret = []
    for a, i in ins.items():
        if i.mnemonic == 'push':
            n = ins.get(a + i.size)
            if n is not None and n.mnemonic == 'ret':
                pushret.append(a)
    L.append(f'- push followed by ret: {len(pushret)} ' + ', '.join(hex(a) for a in pushret[:20]))
    # calls whose return address is consumed (pop right at target / add esp,4 at target)
    popret = [t for t in R['funcs'] if t in ins and ins[t].mnemonic == 'pop']
    L.append(f'- call targets starting with pop (return address consumed as data?): {len(popret)} ' + ', '.join(hex(a) for a in sorted(popret)[:20]))
    # jmp/call register
    jreg = [(a, f'{i.mnemonic} {i.op_str}') for a, i in ins.items() if (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL))
            and i.operands and i.operands[0].type == X.X86_OP_REG]
    L.append(f'- jmp/call through register: {len(jreg)}')
    # jump tables summary
    L.append(f"- jump/call tables resolved: {len(R['jumptables'])}; tables located inside code sections: "
             f"{sum(1 for t, tg in R['jumptables'].values() if in_code(t))}; largest: " +
             ', '.join(f'{a:#x}({len(tg)})' for a, (t, tg) in sorted(R['jumptables'].items(), key=lambda x: -len(x[1][1]))[:8]))
    # targets into middle of instructions
    mid = [(s, d) for s, d in R['edges'] if d in R['owner'] and R['owner'][d] not in (d,) and R['owner'][d] > 0 and d not in ins]
    L.append(f'- edges into the middle of a decoded instruction: {len(mid)}')
    L.append(f"- overlapping instructions: {len(R['overlaps'])}")
    # functions sharing code (blocks reachable from more than one function entry without calls) — tail sharing
    fall_into = [f for f in R['funcs'] if f in ins and any((p in ins and p + ins[p].size == f and not (
        ins[p].mnemonic in ('ret', 'jmp') or ins[p].group(capstone.CS_GRP_JUMP) and not is_jcc(ins[p]))) for p in range(f - 15, f))]
    L.append(f'- function entries reached by fall-through from preceding code (shared bodies / multiple entries): {len(fall_into)}')
    # calls to CodeSeg addresses that are written
    L.append('')
    return {'text': '\n'.join(L) + '\n', 'coverage': cov}


def v2_section(im, G, blocks, tblocks, v2, out):
    L = ['', '## v2: dynamic seeds, 64 KiB rule, order-independent conflicts', '']
    v1p = os.path.join(out, 'cfg-v1.json')
    v1 = json.load(open(v1p)) if os.path.exists(v1p) else None
    dyn = [d for d in v2['dyn'] if in_code(d)]
    L.append(f"Dynamic seeds: {len(v2['dyn'])} executed instruction addresses from `{v2['dyn_path']}` "
             f"(Diamond Heights ticks 100-102), {len(dyn)} in code sections, used as trusted seeds.")
    L.append('')
    if v1:
        L.append('| | v1 | v2 |')
        L.append('|---|---|---|')
        L.append(f"| instructions | {v1['instructions']} | {len(G['insn_at'])} |")
        L.append(f"| basic blocks | {len(v1['blocks'])} | {len(blocks)} |")
        L.append(f"| functions | {len(v1['functions'])} | {len(G['funcs'])} |")
        L.append(f"| trusted blocks (A + dynamic, no heuristic seed) | - | {len(tblocks)} |")
        L.append(f"| trusted instructions | - | {len(v2['trusted']['insn_at'])} |")
        L.append('')
        v1s = set(v1['instruction_starts'])
        v1own = {}
        # executed addresses vs v1
        miss1 = [d for d in dyn if d not in v1s]
        L.append(f"Executed addresses that were **not instruction starts in v1**: {len(miss1)}" +
                 (': ' + ', '.join(hex(x) for x in miss1[:60]) + (' ...' if len(miss1) > 60 else '') if miss1 else '.'))
        # v1 instructions overlapping an executed address (executed address strictly inside)
        v1sorted = sorted(v1s)
        import bisect
        ov1 = []
        for d in dyn:
            k = bisect.bisect_left(v1sorted, d)
            if k < len(v1sorted) and v1sorted[k] == d:
                continue
            if k > 0:
                st = v1sorted[k - 1]
                i = im.insn(st)
                if i is not None and st < d < st + i.size:
                    ov1.append((st, d))
        L.append(f"v1 instructions straddling an executed address: {len(ov1)}" +
                 (': ' + ', '.join(f'{a:#x}(covers {d:#x})' for a, d in ov1[:60]) if ov1 else '.'))
        gone = sorted(set(v1['blocks']) - set(blocks))
        L.append(f"v1 blocks no longer in the map: {len(gone)}; v2 blocks not in v1: {len(set(blocks) - set(v1['blocks']))}.")
        named = [0x47ffe6, 0x480000, 0x481402, 0x52ffd1, 0x530000, 0x5b0000, 0x5b0002, 0x5b0004, 0x5e0000, 0x5e0004]
        L.append('Blocks reported bad by dynamic validation, present in v2? ' +
                 ', '.join(f"{a:#x}:{'PRESENT' if a in set(blocks) else 'gone'}" for a in named))
        L.append(f"Real instruction 0x5dffff present in v2: {0x5dffff in G['insn_at']}.")
        L.append('')
    s2 = set(G['insn_at'])
    miss2 = [d for d in dyn if d not in s2]
    L.append(f"Executed addresses that are not instruction starts in v2: {len(miss2)}" +
             (': ' + ', '.join(hex(x) for x in miss2[:40]) if miss2 else '.'))
    ov2 = []
    for d in dyn:
        o = G['owner'].get(d)
        if o is not None and o != d:
            ov2.append((o, d))
    L.append(f"v2 instructions straddling an executed address: {len(ov2)}" +
             (': ' + ', '.join(f'{a:#x}(covers {d:#x})' for a, d in ov2[:40]) if ov2 else '.'))
    L.append(f"Overlapping instruction starts in v2: {len(G['overlaps'])}.")
    L.append('')
    rem = v2['removed']
    L.append(f"Removed by the 64 KiB rule: {len(rem)} seeds: " + ', '.join(hex(a) for a in sorted(rem)))
    dr = v2['dropped']
    L.append(f"Dropped by the order-independent conflict check: {len(dr)} accepted heuristic seeds:")
    for a in sorted(dr):
        L.append(f"- {a:#x}: {dr[a]}")
    L.append('')
    L.append(f"Re-gated the other side of each dropped conflict: {len(v2['retry'])} seeds, recovered "
             f"{len(v2['recovered'])} ({v2['retry_stats']}): " + ', '.join(hex(a) for a in v2['recovered']))
    L.append('')
    L.append('Outputs: `cfg.json` (now with `block_provenance` parallel to `blocks`, and `blocks_trusted`), '
             '`blocks-all.bin`, `blocks-trusted.bin` (sorted uint32 LE block starts).')
    return '\n'.join(L) + '\n'


def guess_indirect(t):
    if 'ebx*4' in t or '*4' in t:
        return 'table dispatch with computed/register table'
    if t.startswith('call dword ptr [e') and '+' in t:
        return 'call through struct field (window event handler / object vtable)'
    if t.startswith('call e') or t.startswith('jmp e'):
        return 'register target (computed / function pointer variable)'
    if '[0x' in t:
        return 'function-pointer variable at fixed address'
    return 'memory-held target'


def imports_reached(im, ins, start):
    out = set()
    a = start
    for _ in range(60):
        i = ins.get(a) or im.insn(a)
        if i is None:
            break
        for o in i.operands:
            if o.type == X.X86_OP_MEM and o.mem.base == 0 and o.mem.index == 0:
                d = o.mem.disp & 0xFFFFFFFF
                if d in im.imports and (i.group(capstone.CS_GRP_CALL) or i.group(capstone.CS_GRP_JUMP)):
                    out.add(im.imports[d].split('!')[1])
        if i.mnemonic == 'ret':
            break
        if i.mnemonic == 'jmp' and i.operands[0].type == X.X86_OP_IMM:
            a = i.operands[0].imm & 0xFFFFFFFF
            continue
        if i.group(capstone.CS_GRP_CALL) and i.operands[0].type == X.X86_OP_IMM:
            out.add(f'calls {i.operands[0].imm & 0xFFFFFFFF:#x}')
        a += i.size
    return out or {'(no direct import)'}


if __name__ == '__main__':
    main()
