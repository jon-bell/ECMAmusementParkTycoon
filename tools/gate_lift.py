#!/usr/bin/env python3
"""Stage 1 gate: the mechanical lift behaves as rct.exe under the pinned oracle.

For every selected corpus case it runs the oracle (one pinned hook-DLL snapshot for the whole
gate) and the lift (scripts/lift-run.sh, the official lift in out/lift) on the same script and
requires identity on projection `lift` (docs/stage1-design.md, decision 4). It reports `os` and
raw `core` differences as information, observation counts, and wall times.

Coverage cross-check: each case also runs once more on both sides with block coverage (oracle:
RCTHOOK_SPIKE=cover=<blocks-all.bin of the lift's map>; lift: run.js --coverage) and the
executed-block sets are compared. Cover runs are never trace references; they are checked
against the clean runs before their block sets count.

Self-test (principle 6): four known-bad lifts (two lifter mutants, two host mutants) must each be
detected on projection `lift` on at least one case where the clean lift passes.

usage: gate_lift.py [--cases GLOB ...] [--oracle-jobs N] [--lift-jobs N] [--out DIR]
                    [--no-cover] [--no-mutants] [--mutant-cases N] [--lift DIR] [--cache DIR]
exit status 0 iff the gate passes.
"""
import argparse
import bisect
import datetime
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import types
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import rcttrace as T  # noqa: E402

ORACLE_SH = os.path.join(ROOT, 'scripts', 'oracle-run.sh')
LIFT_SH = os.path.join(ROOT, 'scripts', 'lift-run.sh')
LIFTER = os.path.join(ROOT, 'lift', 'lifter.py')
EXE = os.path.join(ROOT, 'game', 'cd', 'English', 'rct.exe')
NODE = '/usr/bin/nodejs'

# The oracle's cover instrument cannot see two kinds of block (oracle/spike.c, oracle/rcthook.c):
# blocks inside the five hook patches (no breakpoint), and blocks of the self-checksummed range
# before frame 2 (breakpoints there are armed at the second frame entry). The lift records the
# same view: run.js --coverage-split-frame 2.
HOOK_PATCHES = [(0x5DF42A, 5), (0x43888E, 6), (0x4385D8, 7), (0x4386EC, 5), (0x426F56, 7)]
CKSUM_LO, CKSUM_HI = 0x42EAE0, 0x431510
SPLIT_FRAME = 2
SECTIONS = {'.text': (0x401000, 0x401000 + 0x1A1A6), 'CODESEG': (0x41C000, 0x41C000 + 0x1CAC5D),
            'CodeSeg': (0x9B3000, 0x9B3000 + 0x9562)}

CLAIM = """\
CLAIM  The mechanical lift of rct.exe 1.08.183 (English) (lift/lifter.py output in {lift}, run by
       lift/runtime + lift/host under Node) behaves as the binary under the pinned oracle: on
       every case below, (1) TRACE STAGE: the lift's trace equals the oracle's on projection
       `lift`, and the lift executes exactly the basic blocks the binary executes; (2) REGISTER
       STAGE: in sampled ticks, the lift's registers, flags and memory writes equal the binary's
       at every basic-block entry.

PROJECTION (required identical)  `lift` (tools/rcttrace.py; docs/stage1-design.md decision 4)
  rng     every RNG draw (tick, call site, value); srand0/srand1 at each tick start (TR_RNG, TR_TICK)
  masked  64-bit FNV-1a hash of DATASEG [0x5F4000,0x9A161C) + DataSeg [0x9A2000,0x9B2301) at each
          tick start with the OS-derived bytes of oracle/mask.h hashed as 0 (TR_MSTATE)
  game    every game_do_command entry (call site, registers, flags), results of injected
          commands, scenario loads, notes (seed, load result, dialogs), run totals (frames,
          ticks, draws)
  input   script inputs as applied (keys, cursor, mouse, chars, files, injected command registers)
REPORTED, NOT REQUIRED
  os      frames and virtual-clock values, window messages delivered/dropped, file opens, header
  core    raw (unmasked) state hashes, per-64-KiB chunk hashes, final hash: identical only if
          the host reproduces Wine's memory layout (a bonus, decision 4)
EXCLUDED  .data/.rdata (C runtime and OS glue; reaches compared state only through DATASEG),
          masked bytes (OS-chosen addresses and handles; the mask is audited by the Stage 0
          gate's layout-shift runs), the framebuffer, sound, timing of the host itself.
COVERAGE (required equal)  set of map-v4 block starts the lift executed vs the oracle's one-shot
          breakpoint hits on every map-v4 block start, both minus what the oracle's instrument
          cannot see (blocks inside its 5 hook patches; checksummed-range blocks
          [0x42EAE0,0x431510) before frame 2), from separate cover runs whose `lift` projection
          must equal the clean runs'.
REGISTER STAGE (required identical)  per case two one-tick windows, chosen from the oracle
          reference trace without looking at the lift: the first tick after the last scripted input
          and the middle tick of the run (each moved to the nearest tick number that occurs once).
          Oracle: RCTHOOK_SPIKE=istep=A:A,regs (every game instruction single-stepped); lift: the
          host's istep capture on {lift_ref} (all flags computed, one function per block).
          tools/stepdiff.py diff --starts <map blocks>: at every block entry eip, the 8 registers,
          eflags & 0xCD5 (CF PF AF ZF SF DF OF), T markers, and the block's memory effect (last
          value of every byte written, stack included). Excluded by stepdiff: registers an OS call
          leaves undefined (ecx, edx, eflags; eax of void imports) in the block after the call;
          OS-chosen values compared by name via osmap.txt. Both capture runs' traces must also
          equal the reference on projection `lift` (non-perturbation; it also checks lift-ref).
TOLERANCE  exact (bit-identical records; equal block sets; identical register streams).
"""

NOT_CERTIFIED = """\
NOT CERTIFIED by a pass: lifted code no case executed (listed under COVERAGE as unvalidated
  instructions); scenarios, seeds, quanta and actions outside the listed cases; saved-game
  loading beyond what the cases do; real mouse/keyboard input; sound enabled; screen sizes other
  than 1024x768; the framebuffer and anything drawn; state outside the projection (masked bytes,
  .data/.rdata); Node versions other than the one recorded; other oracle builds, Wine builds or
  hosts; anything after the last tick of each case. Flag and register faults outside the
  sampled register windows are visible only if they reach compared state (measured: of 13
  single-site stc-drop faults executed in forest-frontiers-open, 10 never reach the trace
  projection nor the framebuffer). The register stage compares the all-flags per-block lift
  (out/lift-ref); the flag-optimised region lift (out/lift) is compared by the trace stage only,
  where dead flags are deliberately not computed.
"""

# Mutants: (name, kind, what). Lifter mutants are lift/lifter.py --mutant builds; host mutants
# are lift/run.js --host-mutant wrappers around the host's bound imports.
MUTANTS = [
    ('adc-nocf', 'lifter', 'lifter: adc ignores CF (lifted as add)'),
    ('stc-ret-drop', 'lifter', 'lifter: an stc immediately before a ret is dropped'),
    ('clock-2ms', 'host', 'host: timeGetTime advances the virtual clock 2 ms per query instead of the pinned quantum'),
    ('systime-plus-1d', 'host', 'host: GetSystemTime answers one day late'),
]

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(f'[{datetime.datetime.now():%H:%M:%S}] {msg}', flush=True)


def sha256_file(p, n=None):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()[:n] if n else h.hexdigest()


def md5_file(p):
    return hashlib.md5(open(p, 'rb').read()).hexdigest()


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
    except OSError:
        return ''


def read_u32s(p):
    data = open(p, 'rb').read()
    return set(struct.unpack(f'<{len(data) // 4}I', data))


# ------------------------------------------------------------------ runs
def run_cmd(cmd, run_dir, env=None, meta_extra=None):
    """Run one oracle or lift run; return {ok, wall_s, log}. Writes gate-meta.json in run_dir."""
    e = dict(os.environ)
    e.pop('TMPDIR', None)
    if env:
        e.update(env)
    t0 = time.time()
    p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=e)
    wall = time.time() - t0
    r = {'ok': p.returncode == 0, 'rc': p.returncode, 'wall_s': round(wall, 1), 'log': p.stdout[-1500:], 'dir': run_dir}
    if os.path.isdir(run_dir):
        meta = {'cmd': cmd, 'rc': p.returncode, 'wall_s': r['wall_s'], 'finished': time.time()}
        meta.update(meta_extra or {})
        with open(os.path.join(run_dir, 'gate-meta.json'), 'w') as f:
            json.dump(meta, f, indent=1)
    return r


def oracle_run(run_dir, script, cache_ok, spike=None, timeout=3600, need=()):
    """Oracle run, reused from the cache if it completed with the same DLL + script (+ spike)."""
    meta = os.path.join(run_dir, 'gate-meta.json')
    if cache_ok and os.path.exists(meta) and T.finished(os.path.join(run_dir, 'trace.bin')) and \
            all(os.path.exists(os.path.join(run_dir, n)) for n in need):
        m = json.load(open(meta))
        return {'ok': True, 'rc': 0, 'wall_s': m.get('wall_s'), 'log': '', 'dir': run_dir, 'cached': True}
    cmd = [ORACLE_SH, run_dir, script] + (['--', f'RCTHOOK_SPIKE={spike}'] if spike else [])
    log(f'oracle {spike.split("=")[0] + " " if spike else ""}run {os.path.relpath(run_dir, ROOT)}')
    r = run_cmd(cmd, run_dir, env={'ORACLE_TIMEOUT': str(timeout)})
    r['cached'] = False
    return r


def lift_run(run_dir, script, lift_dir, extra=(), timeout=14400, env=None):
    log(f'lift run {os.path.relpath(run_dir, ROOT)} {" ".join(extra)}{" " + str(env) if env else ""}')
    cmd = [LIFT_SH, run_dir, script] + (['--'] + list(extra) if extra else [])
    e = {'LIFT_DIR': lift_dir, 'LIFT_TIMEOUT': str(timeout), 'NODE': NODE}
    e.update(env or {})
    r = run_cmd(cmd, run_dir, env=e)
    try:
        r['lift_run'] = json.load(open(os.path.join(run_dir, 'lift-run.json')))
    except (OSError, ValueError):
        r['lift_run'] = None
    return r


# ------------------------------------------------------------------ trace analysis
def counts(recs):
    c = {}
    for r in recs:
        c[r[0]] = c.get(r[0], 0) + 1
    g = lambda k: c.get(T.K[k], 0)  # noqa: E731
    return {'ticks': g('TR_TICK'), 'rng_draws': g('TR_RNG'), 'masked_states': g('TR_MSTATE'),
            'commands': g('TR_COMMAND'), 'injected': g('TR_INJECT'), 'inputs': g('TR_INPUT'),
            'loads': g('TR_LOAD'), 'records_lift_projection': len(T.projection(recs, T.LIFT)),
            'frames': g('TR_FRAME')}


def chunks_at(recs, tick):
    """TR_CHUNK records of the state written at `tick` (index -> (lo, hi))"""
    out, cur = {}, None
    kt, kc = T.K['TR_TICK'], T.K['TR_CHUNK']
    for r in recs:
        if r[0] == kt:
            if cur == tick:
                break
            cur = r[1]
        elif r[0] == kc and cur == tick:
            out[r[1]] = (r[2], r[3])
    return out


def divergence(ra, rb, proj):
    same, rep = T.compare(ra, rb, proj)
    if same:
        return None
    d = {k: rep[k] for k in ('tick', 'kind', 'index', 'a', 'b', 'context', 'chunks') if k in rep}
    if rep['kind'] == 'TR_MSTATE' and 'chunks' not in d:
        ca, cb = chunks_at(ra, rep['tick']), chunks_at(rb, rep['tick'])
        diff = [i for i in sorted(set(ca) | set(cb)) if ca.get(i) != cb.get(i)]
        d['chunks'] = ['%#x-%#x' % T.chunk_range(i) for i in diff]
        d['chunks_note'] = 'raw (unmasked) chunk hashes of that tick; may include layout-only differences'
    return d


# ------------------------------------------------------------------ the map
class Map:
    def __init__(self, cfg_path):
        d = json.load(open(cfg_path))
        self.version = d.get('map_version')
        self.blocks = sorted(d['blocks'])
        self.block_set = set(self.blocks)
        ins = sorted(d['instruction_starts'])
        self.weight = {}
        j = 0
        for i, b in enumerate(self.blocks):
            nb = self.blocks[i + 1] if i + 1 < len(self.blocks) else 1 << 32
            j = bisect.bisect_left(ins, b, j)
            k = bisect.bisect_left(ins, nb, j)
            self.weight[b] = k - j
            j = k
        self.hooked = {b for b in self.blocks if any(a <= b < a + n for a, n in HOOK_PATCHES)}
        self.cksum = {b for b in self.blocks if CKSUM_LO <= b < CKSUM_HI}

    def block_of(self, a):
        i = bisect.bisect_right(self.blocks, a) - 1
        return self.blocks[i] if i >= 0 else None

    def section(self, b):
        for n, (lo, hi) in SECTIONS.items():
            if lo <= b < hi:
                return n
        return None

    def insns(self, S, sect=None):
        return sum(self.weight.get(b, 0) for b in S if sect is None or self.section(b) == sect)

    def totals(self, sect):
        return sum(1 for b in self.blocks if self.section(b) == sect), self.insns(self.blocks, sect)


def lift_view(mp, all_blocks, since_split):
    """What the oracle's cover instrument would record of the lift's execution."""
    if since_split is None:
        since_split = set()
    return ((all_blocks - mp.cksum) | (since_split & mp.cksum)) - mp.hooked


def fmt_addrs(S, n=12):
    s = sorted(S)
    return ' '.join(f'{a:#x}' for a in s[:n]) + (f' ... (+{len(s) - n})' if len(s) > n else '')


# ------------------------------------------------------------------ environment
def lift_info(lift_dir):
    man = json.load(open(os.path.join(lift_dir, 'manifest.json')))
    files = sorted(man['files'] + man.get('regions', {}).get('files', []))
    h = hashlib.sha256()
    for f in files + ['manifest.json']:
        h.update(f.encode())
        h.update(open(os.path.join(lift_dir, f), 'rb').read())
    return man, h.hexdigest()[:16]


def lift_source_hash():
    """the lift host's TR_BUILD id recomputed from the sources on disk (lift/host/host.js buildId:
    SHA-256 over lift/**/*.{js,py,json} except test/ and __pycache__/, first 8 bytes LE)"""
    root = os.path.join(ROOT, 'lift')
    files = []

    def walk(d):
        for e in sorted(os.scandir(d), key=lambda e: e.name):
            if e.is_dir():
                if e.name not in ('test', '__pycache__'):
                    walk(e.path)
            elif os.path.splitext(e.name)[1] in ('.js', '.py', '.json'):
                files.append(e.path)
    walk(root)
    h = hashlib.sha256()
    for f in files:
        h.update(os.path.relpath(f, root).encode())
        h.update(open(f, 'rb').read())
    return f"{int.from_bytes(h.digest()[:8], 'little'):016x}"


def build_mutant_lift(name, cache_root, cfg_path, flags=(), only=None):
    """a known-bad lift: lifter.py --mutant NAME [--mutant-only SITES] [flags] (cached by lifter + map hash)"""
    key = hashlib.sha256((sha256_file(LIFTER) + sha256_file(cfg_path) + md5_file(EXE) + name + ' '.join(flags) +
                          str(only)).encode()).hexdigest()[:12]
    tag = name + (f'-{only.replace(",", "_")}' if only else '') + ('-ref' if flags else '')
    d = os.path.join(cache_root, 'mutant-lifts', f'{tag}-{key}')
    if not os.path.exists(os.path.join(d, 'manifest.json')):
        log(f'building mutant lift {tag} -> {os.path.relpath(d, ROOT)}')
        p = subprocess.run([os.path.join(ROOT, '.venv', 'bin', 'python'), LIFTER, '--exe', EXE, '--map', cfg_path,
                            '--mutant', name, '--out', d + '.tmp'] + list(flags) + (['--mutant-only', only] if only else []),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            raise RuntimeError(f'mutant lift {name} failed:\n{p.stdout[-2000:]}')
        if os.path.exists(d):
            shutil.rmtree(d)
        os.rename(d + '.tmp', d)
    return d, json.load(open(os.path.join(d, 'manifest.json')))['mutant']


# ------------------------------------------------------------------ register stage
# The second instrument (supervisor decision 2026-10-07): per case, a register capture of sampled
# ticks on both sides (oracle RCTHOOK_SPIKE=istep=A:A,regs; lift host istep on the all-flags,
# per-block lift out/lift-ref) compared by tools/stepdiff.py diff: at every block entry eip,
# registers, eflags & 0xCD5, and the memory effect of each block (every written byte).
STEPDIFF = os.path.join(ROOT, 'tools', 'stepdiff.py')
REF_FLAGS = ('--no-flag-opt', '--region-bits', '0')      # how out/lift-ref is built
# register-stage self-test: single-site stc-drop mutants that the trace projection does not see
# on this case (measured: out/status/gate-lift.md, "stc-ret-drop per site")
REG_MUTANT_CASE = 'public/forest-frontiers-open'
REG_MUTANTS = [('stc-ret-drop', '0x425479'), ('stc-ret-drop', '0x4328DC')]


def reg_windows(recs):
    """Deterministic capture windows (one tick each) from the oracle reference trace: the first tick
    after the last scripted input, and the tick in the middle of the run. A window tick t must
    occur exactly once in the run and be followed by tick t+1 (also once): the capture starts at
    the hook of tick t and stops at the hook of t+1, and a tick number repeated after a scenario
    load would restart it on the oracle side."""
    kt, kin = T.K['TR_TICK'], {T.K['TR_INPUT'], T.K['TR_INJECT']}
    ticks, last_in = [], None
    for r in recs:
        if r[0] == kt:
            ticks.append(r[1])
        elif r[0] in kin:
            last_in = len(ticks)
    cnt = Counter(ticks)

    def ok(q):
        return 0 <= q < len(ticks) - 1 and ticks[q] >= 1 and cnt[ticks[q]] == 1 and \
            ticks[q + 1] == ticks[q] + 1 and cnt[ticks[q + 1]] == 1

    def near(p, avoid):
        for dlt in range(len(ticks)):
            for q in (p + dlt, p - dlt):
                if ok(q) and ticks[q] not in avoid:
                    return ticks[q]
        return None
    w = []
    t1 = near(min(last_in or 0, max(0, len(ticks) - 2)), set())
    if t1 is not None:
        w.append(('after-last-input', t1))
    t2 = near(len(ticks) // 2, {t1})
    if t2 is not None:
        w.append(('mid-run', t2))
    return w


_IDENT = re.compile(r'IDENTICAL: (\d+) block entries, (\d+) ticks, (\d+) register comparisons, (\d+) written bytes')
_DIV = re.compile(r'FIRST DIVERGENCE at block entry (\d+) \((.*)\)')


def stepdiff(ctx, ocap, lcap, out_txt):
    with ctx.diff_sem:
        p = subprocess.run([sys.executable, '-I', STEPDIFF, 'diff', ocap, lcap, '--starts', ctx.blocks_all],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with open(out_txt, 'w') as f:
        f.write(p.stdout)
    r = {'rc': p.returncode, 'stepdiff': os.path.relpath(out_txt, ROOT)}
    m = _IDENT.search(p.stdout)
    if p.returncode == 0 and m:
        r.update(identical=True, blocks=int(m[1]), ticks=int(m[2]), regs=int(m[3]), writes=int(m[4]))
        return r
    r['identical'] = False
    m = _DIV.search(p.stdout)
    if m:
        r['index'], r['why'] = int(m[1]), m[2]
        lines = p.stdout[m.start():].splitlines()
        r['detail'] = lines[1:16]
    else:
        r['why'] = 'stepdiff failed'
        r['detail'] = p.stdout.splitlines()[-8:]
    return r


_REGD = re.compile(r'^\s*(\w+): oracle ([0-9a-f]{8}) lift ([0-9a-f]{8})(.*)$')
_OSD = re.compile(r'OS-derived\? oracle (\S+), lift (\S+)\)')
_W = re.compile(r'W \[([0-9a-f]+)\] = ([0-9a-f]+) \((\d+)\)')


def classify_reg_divergence(w, ocap, lcap):
    """A first guess at who is wrong at a register-stage divergence (reporting only: the verdict
    stays FAIL, and an 'instrument' label is a lead for a human, not an excuse):
      'instrument (likely): unmapped OS pointer'  both values lie next to their side's own OS
                    objects (osmap obj/vtbl), but neither is listed;
      'instrument (likely): wider oracle write'   the oracle records a wider write than the lift at
                    the same address with the same low bytes (oracle/spike.c write predictor);
      'OS value on one side'   stepdiff's "OS-derived?" note: one side holds a listed OS value;
      'unclassified'           anything else: a lift or host defect until shown otherwise."""
    sys.path.insert(0, HERE)
    import stepdiff as SD
    od, ld = os.path.join(os.path.dirname(ocap), 'osmap.txt'), os.path.join(os.path.dirname(lcap), 'osmap.txt')
    om, lm = SD.load_osmap(od if os.path.exists(od) else None), SD.load_osmap(ld if os.path.exists(ld) else None)
    oobj = [v for v, n in om.items() if not n.startswith('fn:')]
    lobj = [v for v, n in lm.items() if not n.startswith('fn:')]
    near = lambda v, objs: any(abs(v - o) < 0x1000 for o in objs)  # noqa: E731
    det = w.get('detail', [])
    out = []
    for ln in det:
        m = _REGD.match(ln)
        if m:
            reg, x, y, rest = m[1], int(m[2], 16), int(m[3], 16), m[4]
            n = _OSD.search(rest)
            if n:
                out.append(f'OS value on one side ({reg}: oracle {x:#x} = {n[1]}, lift {y:#x} = {n[2]})')
            elif near(x, oobj) and near(y, lobj):
                out.append(f'instrument (likely): unmapped OS pointer ({reg}: oracle {x:#x} / lift {y:#x} next to '
                           "each side's OS objects)")
            else:
                out.append(f'unclassified ({reg}: oracle {x:#x} lift {y:#x})')
    if w.get('why') == 'memory effect':
        ow = [ln.split(':', 1)[1].strip() for ln in det if ln.strip().startswith('oracle writes:')]
        lw = [ln.split(':', 1)[1].strip() for ln in det if ln.strip().startswith('lift writes:')]
        po = _W.search(ow[0]) if ow else None
        pl = _W.search(lw[0]) if lw else None
        if po and pl and po[1] == pl[1] and int(po[3]) > int(pl[3]) and \
                int(po[2], 16) & ((1 << (8 * int(pl[3]))) - 1) == int(pl[2], 16):
            out.append(f'instrument (likely): wider oracle write (oracle {po[3]} bytes, lift {pl[3]} bytes at {po[1]}, same low '
                       'bytes; e.g. oracle/spike.c records the dword for a 16-bit bts/btr/btc m16, r16)')
        else:
            out.append('unclassified (memory effect)')
    if not out:
        out.append(f"unclassified ({w.get('why')})")
    return out


def reg_window(ctx, cid, path, ref, label, A, lift_dir=None, tag=None, oracle_dir=None):
    """capture tick A on both sides (or reuse the oracle capture in oracle_dir) and compare"""
    spike = f'istep={A}:{A},regs'
    od = oracle_dir or ctx.cdir(f'istep-t{A}', cid, path)
    ld = os.path.join(ctx.out, tag or 'regs', cid, f't{A}')
    fo = ctx.opool.submit(oracle_run, od, path, ctx.cache_ok or oracle_dir is not None, spike, ctx.otimeout, ('istep_regs.bin',))
    fl = ctx.lpool.submit(lift_run, ld, path, lift_dir or ctx.lift_ref, (), ctx.ltimeout, {'RCTHOOK_SPIKE': spike})
    ro, rl = fo.result(), fl.result()
    w = {'label': label, 'tick': A, 'oracle_dir': os.path.relpath(od, ROOT), 'lift_dir': os.path.relpath(ld, ROOT),
         'oracle_wall_s': ro['wall_s'], 'oracle_cached': ro.get('cached'), 'lift_wall_s': rl['wall_s'], 'problems': []}
    ocap, lcap = os.path.join(od, 'istep_regs.bin'), os.path.join(ld, 'istep_regs.bin')
    if not ro['ok'] or not os.path.exists(ocap):
        w['problems'].append('oracle capture run did not complete')
    else:
        d = divergence(ref, T.load(os.path.join(od, 'trace.bin')), 'lift')
        if d:
            w['problems'].append(f"oracle capture run perturbed the trace: tick {d['tick']} {d['kind']}")
        w['oracle_capture_mb'] = round(os.path.getsize(ocap) / 1e6, 1)
    if not rl['ok'] or not os.path.exists(lcap):
        w['problems'].append('lift capture run did not reach quit: ' + str((rl.get('lift_run') or {}).get('error')))
    if os.path.exists(os.path.join(ld, 'trace.bin')):
        # the capture runs use out/lift-ref (all flags, per-block): its trace is checked too
        d = divergence(ref, T.load(os.path.join(ld, 'trace.bin')), 'lift')
        w['lift_trace'] = 'identical (lift projection)' if d is None else \
            f"DIFFERS at tick {d['tick']} ({d['kind']}): {d['a']} | {d['b']}"
    if os.path.exists(ocap) and os.path.exists(lcap):
        w.update(stepdiff(ctx, ocap, lcap, os.path.join(ld, 'stepdiff.txt')))
        if not w.get('identical') and 'index' in w:
            w['classification'] = classify_reg_divergence(w, ocap, lcap)
        if w.get('identical') and not w.get('blocks'):
            w['problems'].append('vacuous: no block entries compared')
    else:
        w['identical'] = False
    w['ok'] = bool(w.get('identical')) and not w['problems']
    return w


def register_case(ctx, cid, path, ref_fut):
    ro = ref_fut.result()
    res = {'case': cid, 'windows': []}
    tp = os.path.join(ro['dir'], 'trace.bin')
    if not ro['ok'] or not os.path.exists(tp):
        res.update(verdict='FAIL', reason='no complete oracle reference')
        return res
    ref = T.load(tp)
    wins = reg_windows(ref)
    if not wins:
        res.update(verdict='FAIL', reason='no capturable window (no tick that occurs once, followed by the next)')
        return res
    with ThreadPoolExecutor(len(wins)) as ex:
        res['windows'] = list(ex.map(lambda lw: reg_window(ctx, cid, path, ref, *lw), wins))
    res['verdict'] = 'PASS' if all(w['ok'] for w in res['windows']) else 'FAIL'
    return res


def reg_self_test(ctx, cases, regres, traces):
    """single-site mutants the trace projection misses must be detected by the register stage"""
    out = []
    path = dict(cases).get(REG_MUTANT_CASE)
    clean = regres.get(REG_MUTANT_CASE)
    for name, only in REG_MUTANTS:
        e = {'mutant': f'{name}@{only}', 'case': REG_MUTANT_CASE, 'what': f'lifter: the stc at {only} (before a ret) is dropped',
             'windows': []}
        out.append(e)
        if path is None or clean is None or not clean['windows']:
            e.update(verdict='NOT RUN', reason=f'{REG_MUTANT_CASE} is not in this gate or has no register windows')
            continue
        ref_lift, _ = build_mutant_lift(name, ctx.cache_root, ctx.cfg, REF_FLAGS, only)
        trace_lift, _ = build_mutant_lift(name, ctx.cache_root, ctx.cfg, (), only)
        tag = f'mutants-reg/{name}-{only}'
        ft = ctx.lpool.submit(lift_run, os.path.join(ctx.out, tag, 'trace', REG_MUTANT_CASE), path, trace_lift, (), ctx.ltimeout)
        ws = []
        for w in clean['windows']:
            ws.append((w, ctx.wpool.submit(reg_window, ctx, REG_MUTANT_CASE, path, traces[REG_MUTANT_CASE][0], w['label'],
                                           w['tick'], ref_lift, tag, os.path.join(ROOT, w['oracle_dir']))))
        rt = ft.result()
        tm = T.load(os.path.join(rt['dir'], 'trace.bin')) if os.path.exists(os.path.join(rt['dir'], 'trace.bin')) else []
        d = divergence(traces[REG_MUTANT_CASE][0], tm, 'lift')
        e['trace_stage'] = 'not detected (identical on projection lift)' if d is None else \
            f"detected at tick {d['tick']} ({d['kind']})"
        for wc, f in ws:
            r = f.result()
            r['clean_identical'] = wc['ok']
            r['clean_index'] = wc.get('index')       # the clean window's first divergence (None: identical)
            e['windows'].append(r)
        # detected: the mutant diverges where the clean lift still agrees with the binary (before the
        # clean window's own first divergence, if it has one)
        det = [r for r in e['windows'] if r.get('identical') is False and 'index' in r and
               (r['clean_identical'] or (r['clean_index'] is not None and r['index'] < r['clean_index']))]
        e['verdict'] = 'DETECTED' if det else 'NOT DETECTED'
    return out


# ------------------------------------------------------------------ main
def case_weight(cid):
    for k, w in (('park-', 10), ('tour-', 5), ('uitour', 5), ('viewopts', 4), ('catalogue', 3)):
        if k in cid:
            return w
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', nargs='*', default=['public/*', 'heldout/*'])
    ap.add_argument('--oracle-jobs', type=int, default=16, help='parallel oracle runs (disk ~160 MB each)')
    ap.add_argument('--lift-jobs', type=int, default=48, help='parallel lift runs')
    ap.add_argument('--out', default=None)
    ap.add_argument('--cache', default=os.path.join(ROOT, 'out', 'gate-lift', 'cache'),
                    help='oracle runs and mutant lifts, reused when DLL md5 + script hash match')
    ap.add_argument('--no-cache', action='store_true', help='do not reuse cached oracle runs')
    ap.add_argument('--lift', default=os.path.join(ROOT, 'out', 'lift'))
    ap.add_argument('--oracle-timeout', type=int, default=3600,
                    help='seconds per oracle run (oracle-run.sh default 600 is too short for park cases under load)')
    ap.add_argument('--lift-timeout', type=int, default=14400, help='seconds per lift run')
    ap.add_argument('--no-cover', action='store_true', help='skip the coverage cross-check (the gate then cannot pass)')
    ap.add_argument('--no-mutants', action='store_true', help='skip the self-test (the gate then cannot pass)')
    ap.add_argument('--mutant-cases', type=int, default=3, help='cases tried per mutant before widening to all')
    ap.add_argument('--lift-ref', default=os.path.join(ROOT, 'out', 'lift-ref'),
                    help='all-flags per-block lift for the register stage (lifter.py --no-flag-opt --region-bits 0)')
    ap.add_argument('--no-regs', action='store_true', help='skip the register stage (the gate then cannot pass)')
    ap.add_argument('--diff-jobs', type=int, default=12, help='parallel stepdiff comparisons (memory ~1-4 GB each)')
    a = ap.parse_args()

    out = a.out or os.path.join(ROOT, 'out', 'gate-lift', datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    os.environ.pop('TMPDIR', None)

    # one oracle DLL snapshot for every oracle run of this gate
    subprocess.run(['make', '-s', '-C', os.path.join(ROOT, 'oracle')], check=True)
    bindir = os.path.join(out, 'oracle-bin')
    os.makedirs(bindir, exist_ok=True)
    shutil.copy2(os.path.join(ROOT, 'out', 'oracle-bin', 'dinput.dll'), bindir)
    os.environ['ORACLE_BIN'] = bindir
    dll_md5 = md5_file(os.path.join(bindir, 'dinput.dll'))

    man, lift_hash = lift_info(a.lift)
    cfg_path = man['map']
    mp = Map(cfg_path)
    cover_file = os.path.join(os.path.dirname(cfg_path), 'blocks-all.bin')
    cover_set = read_u32s(cover_file)
    env_problems = []
    if cover_set != mp.block_set:
        env_problems.append(f'{cover_file} is not the block set of {cfg_path}')
    if man['nblocks'] != len(mp.blocks) or man.get('extra_leaders'):
        env_problems.append(f"lift has {man['nblocks']} blocks (extra leaders {man.get('extra_leaders')}), map {len(mp.blocks)}")
    if man.get('mutant'):
        env_problems.append(f"the lift in {a.lift} is a mutant ({man['mutant']['name']})")
    man_ref, lift_ref_hash = lift_info(a.lift_ref)
    if man_ref.get('flag_opt') or man_ref.get('regions', {}).get('count') or man_ref.get('mutant') or \
            man_ref['map'] != cfg_path or man_ref['nblocks'] != man['nblocks']:
        env_problems.append(f'{a.lift_ref} is not an all-flags per-block lift of {cfg_path}')
    cover_win = 'Z:' + cover_file.replace('/', '\\')
    cover_key = sha256_file(cover_file, 12)

    cases = []
    for path in sorted(glob.glob(os.path.join(ROOT, 'corpus', '*', '*.txt'))):
        cid = os.path.relpath(path, os.path.join(ROOT, 'corpus'))[:-4]
        if any(fnmatch.fnmatch(cid, g) for g in a.cases):
            cases.append((cid, path))
    if not cases:
        print('no corpus cases selected')
        return 2
    cases.sort(key=lambda c: -case_weight(c[0]))

    cache = os.path.join(os.path.abspath(a.cache), dll_md5[:12])
    env = environment(dll_md5, a.lift, man, lift_hash, mp, cfg_path)
    env['lift_ref_dir'] = os.path.relpath(a.lift_ref, ROOT)
    env['lift_ref_generated_sha256_16'] = lift_ref_hash
    with open(os.path.join(out, 'environment.json'), 'w') as f:
        json.dump(env, f, indent=1)
    log(f'gate: {len(cases)} cases -> {out}; oracle dll {dll_md5}; lift {a.lift} ({lift_hash}); map v{mp.version}')

    def cdir(kind, cid, path):
        return os.path.join(cache, kind, cid.replace('/', '__') + '-' + sha256_file(path, 12))

    opool = ThreadPoolExecutor(a.oracle_jobs)
    lpool = ThreadPoolExecutor(a.lift_jobs)
    futs = {}
    for cid, path in cases:
        futs[(cid, 'oracle')] = opool.submit(oracle_run, cdir('ref', cid, path), path, not a.no_cache, None, a.oracle_timeout)
        futs[(cid, 'lift')] = lpool.submit(lift_run, os.path.join(out, 'lift', cid), path, a.lift, (), a.lift_timeout)
        if not a.no_cover:
            futs[(cid, 'oracle-cover')] = opool.submit(oracle_run, cdir('cover-' + cover_key, cid, path), path,
                                                       not a.no_cache, f'cover={cover_win}', a.oracle_timeout,
                                                       ('cover_hits.bin',))
            cd = os.path.join(out, 'lift-cover', cid)
            futs[(cid, 'lift-cover')] = lpool.submit(
                lift_run, cd, path, a.lift, ('--coverage', os.path.join(cd, 'executed_blocks.bin'),
                                             '--coverage-split-frame', str(SPLIT_FRAME)), a.lift_timeout)
    ctx = types.SimpleNamespace(out=out, opool=opool, lpool=lpool, wpool=ThreadPoolExecutor(2 * len(cases) + 8), cdir=cdir,
                                cache_ok=not a.no_cache, otimeout=a.oracle_timeout, ltimeout=a.lift_timeout,
                                lift_ref=a.lift_ref, blocks_all=cover_file, diff_sem=threading.Semaphore(a.diff_jobs),
                                cache_root=os.path.abspath(a.cache), cfg=cfg_path)
    regfuts = {} if a.no_regs else {cid: ctx.wpool.submit(register_case, ctx, cid, path, futs[(cid, 'oracle')])
                                    for cid, path in cases}
    # mutant lifts build while the runs go
    mutant_lifts = {}
    if not a.no_mutants:
        for name, kind, _ in MUTANTS:
            if kind == 'lifter':
                mutant_lifts[name] = build_mutant_lift(name, os.path.abspath(a.cache), cfg_path)
    R = {k: f.result() for k, f in futs.items()}
    regres = {cid: f.result() for cid, f in regfuts.items()}

    report = {'claim': CLAIM.format(lift=os.path.relpath(a.lift, ROOT), lift_ref=os.path.relpath(a.lift_ref, ROOT)), 'not_certified': NOT_CERTIFIED,
              'environment': env, 'environment_problems': env_problems, 'cases': [], 'mutants': [], 'out': out}
    failures = list(env_problems)
    traces = {}
    oracle_builds, lift_builds = set(), set()
    union = {'oracle': set(), 'lift': set(), 'passing': set(), 'public': set(), 'heldout': set()}
    for cid, path in cases:
        c = {'case': cid, 'script': os.path.relpath(path, ROOT), 'heldout': cid.startswith('heldout/')}
        ro, rl = R[(cid, 'oracle')], R[(cid, 'lift')]
        c['oracle_dir'] = os.path.relpath(ro['dir'], ROOT)
        c['lift_dir'] = os.path.relpath(rl['dir'], ROOT)
        c['oracle_wall_s'] = ro['wall_s']
        c['oracle_cached'] = ro.get('cached')
        c['lift_wall_s'] = rl['wall_s']
        lr = rl.get('lift_run') or {}
        c['lift_run_s'] = lr.get('run_s')
        c['lift_error'] = lr.get('error')
        problems = []
        ta = T.load(os.path.join(ro['dir'], 'trace.bin')) if os.path.exists(os.path.join(ro['dir'], 'trace.bin')) else []
        tb = T.load(os.path.join(rl['dir'], 'trace.bin')) if os.path.exists(os.path.join(rl['dir'], 'trace.bin')) else []
        traces[cid] = (ta, tb)
        if not ro['ok']:
            problems.append('oracle run did not complete: ' + ro['log'][-300:])
        if not rl['ok']:
            problems.append('lift run did not reach quit' + (f": {lr.get('error')}" if lr.get('error') else ''))
        ba, bb = T.build_id(ta), T.build_id(tb)
        c['oracle_build'] = f'{ba[0]:016x}' if ba else None
        c['lift_build'] = f'{bb[0]:016x}' if bb else None
        if ba is None or ba[1] != 0:
            problems.append(f'oracle trace has no oracle TR_BUILD ({ba})')
        else:
            oracle_builds.add(ba[0])
        if bb is None or bb[1] != 1:
            problems.append(f'lift trace has no lift-host TR_BUILD ({bb})')
        else:
            lift_builds.add(bb[0])
        c['observations'] = counts(ta)
        o = c['observations']
        if o['ticks'] == 0 or o['rng_draws'] == 0 or o['masked_states'] == 0:
            problems.append('vacuous: the oracle trace has no ticks, RNG draws or masked state hashes')
        d = divergence(ta, tb, 'lift') if ta else {'kind': 'no oracle trace'}
        c['identical'] = d is None and bool(ta)
        c['first_divergence'] = d
        c['os_divergence'] = divergence(ta, tb, 'os') if ta else None
        c['core_divergence'] = divergence(ta, tb, 'core') if ta else None
        # coverage cross-check
        if not a.no_cover:
            c['coverage'] = cov = coverage_case(mp, R[(cid, 'oracle-cover')], R[(cid, 'lift-cover')], ta, tb)
            if cov.get('lift_blocks') is not None:
                union['lift'] |= cov['_lift_all']
            if cov.get('oracle_blocks') is not None:
                union['oracle'] |= cov['_oracle']
                union['heldout' if c['heldout'] else 'public'] |= cov['_oracle']
            if c['identical'] and cov.get('equal') and not problems:
                union['passing'] |= cov['_lift_all']
            if not cov.get('equal'):
                problems.append('coverage: ' + cov.get('reason', 'executed block sets differ'))
        c['trace_verdict'] = 'PASS' if c['identical'] and not [p for p in problems if not p.startswith('coverage')] else 'FAIL'
        if not a.no_regs:
            c['register'] = rg = regres[cid]
            if rg['verdict'] != 'PASS':
                problems.append('register stage: ' + (rg.get('reason') or '; '.join(
                    f"tick {w['tick']}: " + ('; '.join(w['problems']) or f"diverges at block entry {w.get('index')} ({w.get('why')}) [{'; '.join(w.get('classification', []))}]")
                    for w in rg['windows'] if not w['ok'])))
        c['problems'] = problems
        c['verdict'] = 'PASS' if c['identical'] and not problems else 'FAIL'
        if c['verdict'] != 'PASS':
            failures.append(cid)
        report['cases'].append(c)
    if len(oracle_builds) > 1:
        failures.append('mixed oracle builds: ' + ', '.join(f'{b:016x}' for b in oracle_builds))
    if len(lift_builds) > 1:
        failures.append('mixed lift host builds (lift sources changed during the gate): ' + ', '.join(f'{b:016x}' for b in lift_builds))
    report['oracle_builds'] = [f'{b:016x}' for b in oracle_builds]
    report['lift_builds'] = [f'{b:016x}' for b in lift_builds]
    if a.no_regs:
        failures.append('register stage not run (--no-regs)')
    if not a.no_cover:
        report['coverage'] = corpus_coverage(mp, union, cases, report['cases'])
    else:
        failures.append('coverage cross-check not run (--no-cover)')

    # ---------------- self-test
    if a.no_mutants:
        failures.append('self-test not run (--no-mutants)')
    else:
        report['mutants'] = self_test(a, out, mp, report, mutant_lifts, traces, R, cases, lpool, union['lift'])
        for m in report['mutants']:
            if m['verdict'] != 'DETECTED':
                failures.append('mutant:' + m['mutant'])
        if not a.no_regs:
            report['register_mutants'] = reg_self_test(ctx, cases, regres, traces)
            for m in report['register_mutants']:
                if m['verdict'] != 'DETECTED':
                    failures.append('register-mutant:' + m['mutant'])
    opool.shutdown()
    lpool.shutdown()
    ctx.wpool.shutdown()

    for c in report['cases']:
        if 'coverage' in c:
            for k in [k for k in c['coverage'] if k.startswith('_')]:
                del c['coverage'][k]
    now = lift_source_hash()
    if now != env['lift_build_from_sources']:
        failures.append(f"lift sources changed during the gate ({env['lift_build_from_sources']} -> {now})")
    if lift_builds and {f'{b:016x}' for b in lift_builds} != {env['lift_build_from_sources']}:
        failures.append('lift runs do not carry the TR_BUILD id of the lift sources on disk')
    report['verdict'] = 'PASS' if not failures else 'FAIL'
    report['failures'] = failures
    with open(os.path.join(out, 'report.json'), 'w') as f:
        json.dump(report, f, indent=1, default=lambda x: sorted(x) if isinstance(x, set) else str(x))
    text = render(report)
    with open(os.path.join(out, 'report.txt'), 'w') as f:
        f.write(text)
    print(text)
    return 0 if not failures else 1


def coverage_case(mp, ro, rl, ref_oracle, ref_lift):
    cov = {}
    reasons = []
    hits_p = os.path.join(ro['dir'], 'cover_hits.bin')
    lall_p = os.path.join(rl['dir'], 'executed_blocks.bin')
    lsplit_p = f'{lall_p}.since-frame{SPLIT_FRAME}.bin'
    # the cover runs must show the same behaviour as the clean runs before their sets count
    if ro['ok'] and ref_oracle:
        tc = T.load(os.path.join(ro['dir'], 'trace.bin'))
        d = divergence(ref_oracle, tc, 'lift')
        cov['oracle_cover_vs_clean'] = 'identical (lift projection)' if d is None else \
            f"DIFFERS at tick {d['tick']} ({d['kind']}): {d['a']} | {d['b']}"
        if d is not None:
            reasons.append('oracle cover run differs from the clean oracle run')
        hl = open(os.path.join(ro['dir'], 'hook.log'), errors='replace').read() if os.path.exists(os.path.join(ro['dir'], 'hook.log')) else ''
        cov['oracle_cover_log'] = [ln.strip() for ln in hl.splitlines() if 'cover:' in ln][:4]
    else:
        reasons.append('oracle cover run did not complete')
    if rl['ok'] and ref_lift:
        tc = T.load(os.path.join(rl['dir'], 'trace.bin'))
        d = divergence(ref_lift, tc, 'game+input')
        dos = divergence(ref_lift, tc, 'os')
        cov['lift_cover_vs_clean'] = 'identical (game+input, os)' if d is None and dos is None else \
            f"DIFFERS ({'game+input' if d else 'os'}) at tick {(d or dos)['tick']} ({(d or dos)['kind']}): {(d or dos)['a']} | {(d or dos)['b']}"
        if d is not None or dos is not None:
            reasons.append('lift coverage run (per-block dispatch) differs from the clean lift run (region dispatch)')
    else:
        reasons.append('lift coverage run did not reach quit')
    O = read_u32s(hits_p) if os.path.exists(hits_p) else None
    LA = read_u32s(lall_p) if os.path.exists(lall_p) else None
    LS = read_u32s(lsplit_p) if os.path.exists(lsplit_p) else None
    if O is not None:
        cov['oracle_blocks'] = len(O)
        cov['_oracle'] = O
        if not O:
            reasons.append('oracle cover hit list is empty (instrument not armed?)')
        if O - mp.block_set:
            reasons.append(f'{len(O - mp.block_set)} oracle hits are not map blocks')
    if LA is not None:
        cov['lift_blocks'] = len(LA)
        cov['lift_insns'] = mp.insns(LA)
        cov['_lift_all'] = LA
        if LA - mp.block_set:
            reasons.append(f'{len(LA - mp.block_set)} lift blocks are not map blocks')
    if O is not None and LA is not None:
        V = lift_view(mp, LA, LS)
        cov['lift_unobservable_hooked'] = len(LA & mp.hooked)
        cov['lift_unobservable_cksum_before_frame2'] = len((LA & mp.cksum) - (LS or set()))
        only_l, only_o = V - O, O - V
        cov['lift_only'] = len(only_l)
        cov['oracle_only'] = len(only_o)
        cov['lift_only_sample'] = fmt_addrs(only_l)
        cov['oracle_only_sample'] = fmt_addrs(only_o)
        cov['lift_only_insns'] = mp.insns(only_l)
        cov['oracle_only_insns'] = mp.insns(only_o)
        if only_l or only_o:
            reasons.append(f'executed block sets differ: lift-only {len(only_l)}, oracle-only {len(only_o)}')
    cov['equal'] = not reasons
    if reasons:
        cov['reason'] = '; '.join(reasons)
    return cov


def corpus_coverage(mp, union, cases, rcases):
    res = {'sections': {}}
    for s in SECTIONS:
        nb, ni = mp.totals(s)
        res['sections'][s] = {
            'blocks_total': nb, 'insns_total': ni,
            'oracle_blocks': sum(1 for b in union['oracle'] if mp.section(b) == s), 'oracle_insns': mp.insns(union['oracle'], s),
            'lift_insns': mp.insns(union['lift'], s), 'validated_insns': mp.insns(union['passing'], s),
            'public_insns': mp.insns(union['public'], s), 'heldout_insns': mp.insns(union['heldout'], s)}
    tot = sum(mp.weight.values())
    res['all'] = {'insns_total': tot, 'oracle_insns': mp.insns(union['oracle']), 'lift_insns': mp.insns(union['lift']),
                  'validated_insns': mp.insns(union['passing']), 'unvalidated_insns': tot - mp.insns(union['passing'])}
    res['heldout_only_codeseg_insns'] = mp.insns(union['heldout'] - union['public'], 'CODESEG')
    res['public_only_codeseg_insns'] = mp.insns(union['public'] - union['heldout'], 'CODESEG')
    return res


def mutant_sites_executed(mp, sites, cov_blocks):
    blocks = {mp.block_of(int(s, 16)) for s in sites}
    return len(blocks & cov_blocks)


def self_test(a, out, mp, report, mutant_lifts, traces, R, cases, lpool, lift_union):
    passing = [c for c in report['cases'] if c.get('trace_verdict') == 'PASS']
    passing.sort(key=lambda c: c['lift_wall_s'] or 1e9)
    path_of = dict(cases)
    results = []
    for name, kind, what in MUTANTS:
        entry = {'mutant': name, 'kind': kind, 'what': what, 'runs': []}
        if kind == 'lifter':
            lift_dir, info = mutant_lifts[name]
            entry['lift'] = os.path.relpath(lift_dir, ROOT)
            entry['sites'] = len(info['sites'])
            extra = ()
            # only cases whose clean lift executed a mutated site can observe the mutant
            cand = []
            for c in passing:
                cb = R.get((c['case'], 'lift-cover'))
                p = os.path.join(cb['dir'], 'executed_blocks.bin') if cb else None
                n = mutant_sites_executed(mp, info['sites'], read_u32s(p)) if p and os.path.exists(p) else None
                if n:
                    cand.append((c, n))
            entry['reachable_cases'] = len(cand)
            entry['sites_executed_by_corpus'] = len({mp.block_of(int(x, 16)) for x in info['sites']} & lift_union)
        else:
            lift_dir, extra = a.lift, ('--host-mutant', name)
            cand = [(c, None) for c in passing]
        if not cand:
            entry['verdict'] = 'NOT DETECTED'
            entry['reason'] = 'no passing case executes a mutated site' if kind == 'lifter' else 'no passing case'
            results.append(entry)
            continue

        def run_batch(batch):
            fs = {}
            for c, n in batch:
                d = os.path.join(out, 'mutants', name, c['case'])
                fs[c['case']] = (lpool.submit(lift_run, d, path_of[c['case']], lift_dir, extra, a.lift_timeout), n)
            for cid, (f, n) in fs.items():
                r = f.result()
                run = {'case': cid, 'sites_executed': n, 'dir': os.path.relpath(r['dir'], ROOT), 'lift_ok': r['ok'],
                       'lift_error': (r.get('lift_run') or {}).get('error')}
                tm = T.load(os.path.join(r['dir'], 'trace.bin')) if os.path.exists(os.path.join(r['dir'], 'trace.bin')) else []
                ref = traces[cid][0]
                d = divergence(ref, tm, 'lift')
                run['detected'] = d is not None
                run['first_divergence'] = d
                if d is None:
                    dos = divergence(ref, tm, 'os')
                    run['os_divergence'] = dos
                    run['why_not'] = 'only os records differ' if dos else 'no difference in any compared record'
                entry['runs'].append(run)

        log(f'self-test {name}: {min(len(cand), a.mutant_cases)} of {len(cand)} candidate cases')
        run_batch(cand[:a.mutant_cases])
        if not any(r['detected'] for r in entry['runs']) and len(cand) > a.mutant_cases:
            log(f'self-test {name}: not detected yet, widening to {len(cand) - a.mutant_cases} more cases')
            run_batch(cand[a.mutant_cases:])
        entry['verdict'] = 'DETECTED' if any(r['detected'] for r in entry['runs']) else 'NOT DETECTED'
        results.append(entry)
    return results


def environment(dll_md5, lift_dir, man, lift_hash, mp, cfg_path):
    return {'oracle_dll_md5': dll_md5,
            'oracle_build_make': sh(f"make -s -pn -C '{ROOT}/oracle' 2>/dev/null | sed -n 's/^BUILD_ID := //p' | head -1"),
            'lift_dir': os.path.relpath(lift_dir, ROOT), 'lift_generated_sha256_16': lift_hash,
            'lift_build_from_sources': lift_source_hash(),
            'lifter_sha256_16': sha256_file(LIFTER, 16),
            'lift_flag_opt': man.get('flag_opt'), 'lift_regions': man.get('regions', {}).get('count'),
            'map': os.path.relpath(cfg_path, ROOT), 'map_version': mp.version, 'map_blocks': len(mp.blocks),
            'map_insns': sum(mp.weight.values()), 'map_sha256_16': sha256_file(cfg_path, 16),
            'node': sh(f'{NODE} --version'), 'wine': sh('wine --version'), 'kernel': sh('uname -r'),
            'os': sh('. /etc/os-release && echo $PRETTY_NAME'), 'rct_md5': md5_file(EXE),
            'git': sh(f"git -C '{ROOT}' describe --always --dirty")}


def pct(a, b):
    return f'{100.0 * a / b:5.1f}%' if b else '  n/a'


def render(rep):
    L = ['=' * 78, 'STAGE 1 GATE: the mechanical lift', '=' * 78, rep['claim']]
    L.append('INPUT DISTRIBUTION (corpus cases, each run once on each side; H = held-out)')
    for c in rep['cases']:
        L.append(f"  {'H' if c['heldout'] else 'P'} {c['case']:42s} {c['script']}")
    L.append('')
    L.append(rep['not_certified'])
    L.append('ENVIRONMENT')
    for k, v in rep['environment'].items():
        L.append(f'  {k:26s} {v}')
    L.append(f"  oracle builds (TR_BUILD)   {', '.join(rep.get('oracle_builds', []))}")
    L.append(f"  lift host builds (TR_BUILD) {', '.join(rep.get('lift_builds', []))}")
    for p in rep['environment_problems']:
        L.append(f'  PROBLEM: {p}')
    L.append('')
    L.append('RESULTS  verdict = trace stage AND coverage AND register stage; TRACE STAGE detail below')
    L.append('         (projection lift; walls in seconds: oracle / lift / ratio; c = oracle run reused from the cache)')
    tot = {}
    for c in rep['cases']:
        o = c['observations']
        for k, v in o.items():
            tot[k] = tot.get(k, 0) + v
        ow, lw = c['oracle_wall_s'] or 0, c['lift_wall_s'] or 0
        rg = c.get('register', {}).get('verdict', '-')
        L.append(f"  {c['verdict']:4s} trace={c.get('trace_verdict', '-'):4s} regs={rg:4s} {'H' if c['heldout'] else 'P'} {c['case']:38s} ticks={o['ticks']:6d} rng={o['rng_draws']:7d} "
                 f"mstate={o['masked_states']:6d} cmds={o['commands']:5d} inputs={o['inputs']:5d}  "
                 f"{ow:6.0f}{'c' if c.get('oracle_cached') else ' '}/{lw:6.0f} x{(lw / ow) if ow else 0:4.1f}")
        d = c['first_divergence']
        if d:
            L.append(f"        first divergence (lift) at tick {d.get('tick')} ({d.get('kind')}), record {d.get('index')}")
            for x in d.get('context', [])[-3:]:
                L.append(f'            {x}')
            L.append(f"          oracle: {d.get('a')}")
            L.append(f"          lift:   {d.get('b')}")
            if d.get('chunks'):
                L.append(f"          raw chunks differing at that tick: {', '.join(d['chunks'][:12])}")
        for p in c['problems']:
            L.append(f'        problem: {p}')
        if c.get('os_divergence'):
            x = c['os_divergence']
            L.append(f"        info: os differs at tick {x['tick']} ({x['kind']}): {x['a']} | {x['b']}")
        if c.get('core_divergence'):
            x = c['core_divergence']
            L.append(f"        info: raw core differs at tick {x['tick']} ({x['kind']}): {x['a']} | {x['b']}"
                     + (f" chunks {', '.join(x['chunks'][:8])}" if x.get('chunks') else ''))
    npass = sum(c['verdict'] == 'PASS' for c in rep['cases'])
    L.append(f"  {npass} of {len(rep['cases'])} cases pass "
             f"(public {sum(c['verdict'] == 'PASS' for c in rep['cases'] if not c['heldout'])}/"
             f"{sum(not c['heldout'] for c in rep['cases'])}, held-out "
             f"{sum(c['verdict'] == 'PASS' for c in rep['cases'] if c['heldout'])}/{sum(c['heldout'] for c in rep['cases'])})")
    L.append(f"  observations compared (oracle side): {tot.get('ticks', 0)} ticks, {tot.get('rng_draws', 0)} RNG draws, "
             f"{tot.get('masked_states', 0)} masked state hashes, {tot.get('commands', 0)} game commands, "
             f"{tot.get('inputs', 0)} inputs, {tot.get('records_lift_projection', 0)} records in projection lift")

    if 'coverage' in rep:
        L.append('')
        L.append('COVERAGE CROSS-CHECK (executed map-v4 block starts: lift run.js --coverage vs oracle cover=)')
        for c in rep['cases']:
            cv = c.get('coverage', {})
            L.append(f"  {'EQUAL' if cv.get('equal') else 'DIFF ':5s} {c['case']:40s} lift {cv.get('lift_blocks', '-')!s:>6} blocks "
                     f"/ oracle {cv.get('oracle_blocks', '-')!s:>6}; lift-only {cv.get('lift_only', '-')}, oracle-only "
                     f"{cv.get('oracle_only', '-')} (unobservable by the oracle: hooked {cv.get('lift_unobservable_hooked', '-')}, "
                     f"cksum<frame2 {cv.get('lift_unobservable_cksum_before_frame2', '-')})")
            if not cv.get('equal'):
                L.append(f"        {cv.get('reason')}")
                if cv.get('lift_only'):
                    L.append(f"        lift-only ({cv['lift_only_insns']} insns): {cv['lift_only_sample']}")
                if cv.get('oracle_only'):
                    L.append(f"        oracle-only ({cv['oracle_only_insns']} insns): {cv['oracle_only_sample']}")
            for k in ('oracle_cover_vs_clean', 'lift_cover_vs_clean'):
                if cv.get(k) and 'DIFFERS' in cv[k]:
                    L.append(f'        {k}: {cv[k]}')
        cg = rep['coverage']
        L.append('')
        L.append('  instruction-weighted coverage of the map (union over the corpus):')
        L.append(f"  {'section':8s} {'insns':>8s} {'oracle exec':>18s} {'lift exec':>18s} {'validated':>18s}")
        for s, v in cg['sections'].items():
            t = v['insns_total']
            L.append(f"  {s:8s} {t:8d} {v['oracle_insns']:9d} {pct(v['oracle_insns'], t)} {v['lift_insns']:9d} "
                     f"{pct(v['lift_insns'], t)} {v['validated_insns']:9d} {pct(v['validated_insns'], t)}")
        al = cg['all']
        L.append(f"  {'all':8s} {al['insns_total']:8d} {al['oracle_insns']:9d} {pct(al['oracle_insns'], al['insns_total'])} "
                 f"{al['lift_insns']:9d} {pct(al['lift_insns'], al['insns_total'])} {al['validated_insns']:9d} "
                 f"{pct(al['validated_insns'], al['insns_total'])}")
        cs = cg['sections']['CODESEG']
        L.append("  (oracle exec omits what its instrument cannot see: blocks in hook patches, checksummed blocks before frame 2)")
        L.append(f"  validated = executed by a case that passes (trace identical, block sets equal). UNVALIDATED: "
                 f"{al['unvalidated_insns']} of {al['insns_total']} lifted instructions "
                 f"({pct(al['unvalidated_insns'], al['insns_total']).strip()}) are executed by no passing case.")
        L.append(f"  CODESEG: public cases reach {cs['public_insns']} ({pct(cs['public_insns'], cs['insns_total']).strip()}), "
                 f"held-out {cs['heldout_insns']} ({pct(cs['heldout_insns'], cs['insns_total']).strip()}); held-out-only "
                 f"{cg['heldout_only_codeseg_insns']}, public-only {cg['public_only_codeseg_insns']} instructions. "
                 f"Target (design): >= 50% of CODESEG.")
    if any('register' in c for c in rep['cases']):
        L.append('')
        L.append('REGISTER STAGE (tools/stepdiff.py diff per window: block entries / ticks / register comparisons / written bytes)')
        tb = tr = tw = 0
        for c in rep['cases']:
            rg = c['register']
            L.append(f"  {rg['verdict']:4s} {c['case']}" + (f"  [{rg['reason']}]" if rg.get('reason') else ''))
            for w in rg['windows']:
                if w.get('identical'):
                    tb, tr, tw = tb + w['blocks'], tr + w['regs'], tw + w['writes']
                    st = f"IDENTICAL {w['blocks']} blocks, {w['ticks']} ticks, {w['regs']} regs, {w['writes']} bytes"
                else:
                    st = f"DIVERGES at block entry {w.get('index')} ({w.get('why')})"
                L.append(f"        tick {w['tick']:6d} ({w['label']:16s}) {st}; oracle capture {w.get('oracle_capture_mb', '-')} MB, "
                         f"walls {w['oracle_wall_s']}{'c' if w.get('oracle_cached') else ''}/{w['lift_wall_s']} s")
                for x in w.get('detail', [])[-4:] if not w.get('identical') else []:
                    L.append(f'            {x}')
                for x in w.get('classification', []):
                    L.append(f'          classification: {x}')
                for p in w['problems']:
                    L.append(f'          problem: {p}')
                if w.get('lift_trace') and 'DIFFERS' in w['lift_trace']:
                    L.append(f"          lift-ref trace: {w['lift_trace']}")
        L.append(f'  compared in total: {tb} block entries, {tr} register comparisons, {tw} written bytes')
    if rep['mutants']:
        L.append('')
        L.append('SELF-TEST, TRACE STAGE (known-bad lifts must be detected on projection lift, on a case the clean lift passes)')
        for m in rep['mutants']:
            extra = f" sites={m['sites']} executed-by-corpus={m.get('sites_executed_by_corpus')} reachable-passing-cases={m.get('reachable_cases')}" \
                if m['kind'] == 'lifter' else ''
            L.append(f"  {m['verdict']:12s} {m['mutant']:16s} {m['what']}{extra}" + (f"  [{m['reason']}]" if m.get('reason') else ''))
            for r in m['runs']:
                d = r['first_divergence']
                if d:
                    L.append(f"      {r['case']}: DETECTED at tick {d['tick']} ({d['kind']})"
                             + (f", mutated blocks executed by the clean lift: {r['sites_executed']}" if r['sites_executed'] else ''))
                    L.append(f"          oracle: {d['a']}")
                    L.append(f"          mutant: {d['b']}")
                    if not r['lift_ok']:
                        L.append(f"          (the mutant run did not reach quit: {r['lift_error']})")
                else:
                    L.append(f"      {r['case']}: not detected ({r.get('why_not')})")
    if rep.get('register_mutants'):
        L.append('')
        L.append('SELF-TEST, REGISTER STAGE (faults the trace stage misses must be detected by the register stage)')
        for m in rep['register_mutants']:
            L.append(f"  {m['verdict']:12s} {m['mutant']:24s} {m['what']} on {m['case']}" + (f"  [{m['reason']}]" if m.get('reason') else ''))
            if m.get('trace_stage'):
                L.append(f"      trace stage: {m['trace_stage']}")
            for w in m['windows']:
                st = 'identical (not detected)' if w.get('identical') else f"diverges at block entry {w.get('index')} ({w.get('why')})"
                cl = 'clean window identical' if w['clean_identical'] else f"clean window's first divergence at block entry {w.get('clean_index')}"
                L.append(f"      tick {w['tick']} ({w['label']}): {st}; {cl}")
                for x in w.get('detail', [])[:10] if not w.get('identical') else []:
                    L.append(f'            {x}')
    L.append('')
    L.append(f"VERDICT: {rep['verdict']}" + (f"  (failures: {', '.join(rep['failures'])})" if rep['failures'] else ''))
    return '\n'.join(L) + '\n'


if __name__ == '__main__':
    sys.exit(main())
