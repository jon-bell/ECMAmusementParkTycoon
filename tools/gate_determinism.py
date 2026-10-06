#!/usr/bin/env python3
"""Stage 0 gate: the pinned oracle is deterministic.

Runs every corpus case N times as independent oracle processes (fresh prefix copy, own X
server, own wineserver, run concurrently), and requires the traces to be identical. Then it
proves it can fail: known-bad variants (mutants) of one case must be detected, in the core
projection, no earlier than the point where they were introduced.

usage: gate_determinism.py [--runs N] [--jobs J] [--out DIR] [--cases GLOB ...] [--no-mutants]
exit status 0 iff the gate passes.
"""
import argparse
import datetime
import fnmatch
import glob
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import rcttrace as T  # noqa: E402

RUN_SH = os.path.join(ROOT, 'scripts', 'oracle-run.sh')

CLAIM = """\
CLAIM  rct.exe 1.08.183 (English), run under the pinned oracle, is deterministic: independent
       runs on the same input produce the same behaviour. Runs are separate processes on fresh
       prefix copies, run concurrently, and deliberately differ in X display, start time,
       run-directory length and environment size.

PROJECTION (compared)
  core   every RNG draw (tick, call site, value); RNG state (srand0, srand1) at each tick start;
         64-bit FNV-1a hash of DATASEG [0x5F4000,0x9A161C) + DataSeg [0x9A2000,0x9B2301) at each
         tick start, also per 64 KiB chunk; final state hash at quit.
  game   core + every entry to game_do_command (0x426F56) with registers, results (registers and
         flags) of injected commands, scenario loads, run totals (frames, ticks, draws).
  input  script inputs as applied (keys, cursor, mouse events, injected command registers).
  Clean runs must agree on game+input. Mutants must be detected by core alone.
EXCLUDED (not compared, and why)
  .data/.rdata (0x5E7000-0x5F3F74): C runtime and OS glue (heap and DirectX pointers, input
         queues); effects on the game reach DATASEG, which is compared.
  os records: frame boundaries and virtual clock values, window messages, file opens. They are
         OS-side inputs; differences are reported as warnings, not failures.
  framebuffer and window contents: not compared in Stage 0.
TOLERANCE  exact (bit-identical records).
"""

NOT_CERTIFIED = """\
NOT CERTIFIED by a pass: scenarios, seeds and actions outside the cases listed; locked
scenarios 5-21; saved-game loading; UI-level mouse/keyboard input; sound enabled; screen sizes
other than 1024x768; Wine builds other than the one recorded; other hosts; anything after the
last tick of each case.
"""

# Mutant definitions, applied to MUTANT_CASE. Each must be detected (core projection), and not
# before `after_tick` (an earlier divergence would itself be nondeterminism).
MUTANT_CASE = 'public/dynamite-dunes-open'
MUTANT_TICK = 1500
MUTANTS = [
    {'name': 'realtime-clock', 'what': 'time pins removed (RCTHOOK_REALTIME=1): wall clock seeds the RNG',
     'env': ['RCTHOOK_REALTIME=1'], 'after_tick': 0},
    {'name': 'rng-bitflip', 'what': f'srand0 bit 0 flipped at tick {MUTANT_TICK}',
     'insert': f'tick {MUTANT_TICK} poke 0x6E3B88 0x01', 'after_tick': MUTANT_TICK},
    {'name': 'cash-bitflip', 'what': f'park cash (0x87C3B4) bit 0 flipped at tick {MUTANT_TICK}',
     'insert': f'tick {MUTANT_TICK} poke 0x87C3B4 0x01', 'after_tick': MUTANT_TICK},
    {'name': 'dropped-command', 'what': 'SET_PARK_OPEN command removed from the input',
     'drop': 'cmd 33', 'after_tick': 0},
]


def run_oracle(run_dir, script, env=()):
    cmd = [RUN_SH, run_dir, script] + (['--'] + list(env) if env else [])
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return {'dir': run_dir, 'ok': p.returncode == 0, 'log': p.stdout[-2000:]}


def stats(recs):
    c = {}
    for r in recs:
        c[r[0]] = c.get(r[0], 0) + 1
    g = lambda k: c.get(T.K[k], 0)  # noqa: E731
    return {'ticks': g('TR_TICK'), 'rng_draws': g('TR_RNG'), 'state_hashes': g('TR_STATE'),
            'chunk_hashes': g('TR_CHUNK'), 'commands': g('TR_COMMAND'), 'injected': g('TR_INJECT'),
            'loads': g('TR_LOAD'), 'records': len(recs)}


def run_dir(out, cid, i):
    # Runs deliberately differ in directory-name length and environment size: the process
    # environment and paths shift heap and stack contents, which must not reach the game.
    return os.path.join(out, cid, f'run{i}' + ('-' + 'v' * (13 * i) if i else ''))


def run_env(i):
    return (f'ORACLE_ENV_PAD={"x" * (97 * i)}',) if i else ()


def mutant_script(src, m, dst):
    lines = open(src).read().splitlines()
    if 'drop' in m:
        lines = [ln for ln in lines if m['drop'] not in ln.split('#')[0]]
    if 'insert' in m:
        # actions run in file order: insert before the first action at or after the mutant tick
        idx = len(lines)
        for i, ln in enumerate(lines):
            t = ln.split('#')[0].split()
            if len(t) >= 2 and t[0] == 'tick' and int(t[1], 0) >= MUTANT_TICK:
                idx = i
                break
        lines.insert(idx, m['insert'] + '   # mutant')
    with open(dst, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--runs', type=int, default=2, help='independent runs per case (default 2)')
    ap.add_argument('--jobs', type=int, default=min(12, os.cpu_count() or 4))
    ap.add_argument('--out', default=None)
    ap.add_argument('--cases', nargs='*', default=['public/*', 'heldout/*'])
    ap.add_argument('--no-mutants', action='store_true')
    a = ap.parse_args()
    if a.runs < 2:
        ap.error('--runs must be at least 2')

    out = a.out or os.path.join(ROOT, 'out', 'gate', datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    os.makedirs(out, exist_ok=True)
    subprocess.run(['make', '-s', '-C', os.path.join(ROOT, 'oracle')], check=True)
    # every run of this gate uses one snapshot of the hook DLL
    bindir = os.path.join(out, 'bin')
    os.makedirs(bindir, exist_ok=True)
    shutil.copy2(os.path.join(ROOT, 'out', 'oracle-bin', 'dinput.dll'), bindir)
    os.environ['ORACLE_BIN'] = bindir

    cases = []
    for path in sorted(glob.glob(os.path.join(ROOT, 'corpus', '*', '*.txt'))):
        cid = os.path.relpath(path, os.path.join(ROOT, 'corpus'))[:-4]
        if any(fnmatch.fnmatch(cid, g) for g in a.cases):
            cases.append((cid, path))
    if not cases:
        print('no corpus cases selected')
        return 2

    jobs = []
    for cid, path in cases:
        for i in range(a.runs):
            jobs.append((cid, i, run_dir(out, cid, i), path, run_env(i)))
    mutant_jobs = []
    if not a.no_mutants:
        src = dict(cases).get(MUTANT_CASE) or os.path.join(ROOT, 'corpus', MUTANT_CASE + '.txt')
        for m in MUTANTS:
            d = os.path.join(out, 'mutants', m['name'])
            os.makedirs(d, exist_ok=True)
            script = os.path.join(d, 'script-in.txt')
            mutant_script(src, m, script)
            mutant_jobs.append((m, os.path.join(d, 'run'), script, tuple(m.get('env', ()))))
        if MUTANT_CASE not in dict(cases):   # the mutants need clean reference runs
            for i in range(a.runs):
                jobs.append((MUTANT_CASE, i, run_dir(out, MUTANT_CASE, i), src, run_env(i)))
            cases.append((MUTANT_CASE, src))

    print(f'gate: {len(jobs)} clean runs, {len(mutant_jobs)} mutant runs, {a.jobs} at a time -> {out}')
    with ThreadPoolExecutor(a.jobs) as ex:
        futs = {ex.submit(run_oracle, d, s, e): (cid, i) for cid, i, d, s, e in jobs}
        mfuts = {ex.submit(run_oracle, d, s, e): m['name'] for m, d, s, e in mutant_jobs}
        results = {futs[f]: f.result() for f in futs}
        mresults = {mfuts[f]: f.result() for f in mfuts}

    report = {'claim': CLAIM, 'not_certified': NOT_CERTIFIED, 'runs_per_case': a.runs, 'cases': [],
              'mutants': [], 'environment': environment()}
    failures = []
    for cid, path in cases:
        c = {'case': cid, 'script': os.path.relpath(path, ROOT)}
        runs = [results[(cid, i)] for i in range(a.runs)]
        bad = [r for r in runs if not r['ok']]
        if bad:
            c['verdict'] = 'FAIL'
            c['reason'] = 'run did not complete'
            c['detail'] = bad[0]['dir'] + '\n' + bad[0]['log']
            failures.append(cid)
            report['cases'].append(c)
            continue
        traces = [T.load(os.path.join(r['dir'], 'trace.bin')) for r in runs]
        c['observations'] = stats(T.projection(traces[0], T.PROJECTIONS['game+input']))
        c['comparisons'] = []
        ok = True
        for i in range(1, a.runs):
            same, rep = T.compare(traces[0], traces[i], 'game+input')
            os_same, os_rep = T.compare(traces[0], traces[i], 'os')
            entry = {'runs': f'run0 vs run{i}', 'identical': same}
            if not same:
                ok = False
                entry['first_divergence'] = {k: rep[k] for k in ('tick', 'kind', 'a', 'b', 'context', 'chunks') if k in rep}
            if not os_same:
                entry['os_warning'] = {k: os_rep[k] for k in ('kind', 'a', 'b') if k in os_rep}
            c['comparisons'].append(entry)
        o = c['observations']
        if o['ticks'] == 0 or o['rng_draws'] == 0 or o['state_hashes'] == 0:
            ok = False
            c['vacuous'] = 'case observed no ticks, RNG draws or state hashes'
        c['verdict'] = 'PASS' if ok else 'FAIL'
        if not ok:
            failures.append(cid)
        report['cases'].append(c)

    if mutant_jobs:
        ref = T.load(os.path.join(results[(MUTANT_CASE, 0)]['dir'], 'trace.bin')) if results[(MUTANT_CASE, 0)]['ok'] else None
        for m, d, s, e in mutant_jobs:
            r = mresults[m['name']]
            entry = {'mutant': m['name'], 'what': m['what'], 'case': MUTANT_CASE}
            if not r['ok'] or ref is None:
                entry['verdict'] = 'FAIL'
                entry['reason'] = 'run did not complete' if not r['ok'] else 'reference run missing'
                entry['detail'] = r['log']
            else:
                same, rep = T.compare(ref, T.load(os.path.join(d, 'trace.bin')), 'core')
                if same:
                    entry['verdict'] = 'FAIL'
                    entry['reason'] = 'not detected'
                elif rep['tick'] < m['after_tick']:
                    entry['verdict'] = 'FAIL'
                    entry['reason'] = f"diverged at tick {rep['tick']}, before the mutation at tick {m['after_tick']}"
                else:
                    entry['verdict'] = 'DETECTED'
                if not same:
                    entry['first_divergence'] = {k: rep[k] for k in ('tick', 'kind', 'a', 'b', 'chunks') if k in rep}
            if entry['verdict'] != 'DETECTED':
                failures.append('mutant:' + m['name'])
            report['mutants'].append(entry)

    report['verdict'] = 'PASS' if not failures else 'FAIL'
    report['failures'] = failures
    with open(os.path.join(out, 'report.json'), 'w') as f:
        json.dump(report, f, indent=1)
    text = render(report)
    with open(os.path.join(out, 'report.txt'), 'w') as f:
        f.write(text)
    print(text)
    return 0 if not failures else 1


def environment():
    def sh(cmd):
        try:
            return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True).stdout.strip()
        except OSError:
            return ''
    return {'wine': sh('wine --version'), 'xvfb': sh("dpkg-query -W -f='${Version}' xvfb"),
            'kernel': sh('uname -r'), 'os': sh('. /etc/os-release && echo $PRETTY_NAME'),
            'rct_md5': sh(f"md5sum '{ROOT}/game/cd/English/rct.exe' | cut -d' ' -f1"),
            'hook_md5': sh(f"md5sum '{os.environ.get('ORACLE_BIN', '')}/dinput.dll' | cut -d' ' -f1"),
            'git': sh(f"git -C '{ROOT}' describe --always --dirty")}


def render(rep):
    L = ['=' * 78, 'STAGE 0 GATE: oracle determinism', '=' * 78, rep['claim']]
    L.append('INPUT DISTRIBUTION (cases; each run %d times, concurrently, as independent processes)' % rep['runs_per_case'])
    for c in rep['cases']:
        L.append(f"  {c['case']:34s} {c['script']}")
    L.append('')
    L.append(NOT_CERTIFIED)
    L.append('ENVIRONMENT  ' + ', '.join(f'{k}={v}' for k, v in rep['environment'].items()))
    L.append('')
    L.append('RESULTS')
    tot = {}
    for c in rep['cases']:
        o = c.get('observations', {})
        for k, v in o.items():
            tot[k] = tot.get(k, 0) + v
        L.append(f"  {c['verdict']:5s} {c['case']:34s} ticks={o.get('ticks', 0):6d} rng={o.get('rng_draws', 0):7d} "
                 f"states={o.get('state_hashes', 0):6d} chunks={o.get('chunk_hashes', 0):7d} cmds={o.get('commands', 0)}")
        for cmp in c.get('comparisons', []):
            if not cmp['identical']:
                fd = cmp['first_divergence']
                L.append(f"        {cmp['runs']}: first divergence at tick {fd['tick']} ({fd['kind']})")
                L.append(f"          A: {fd['a']}")
                L.append(f"          B: {fd['b']}")
                if fd.get('chunks'):
                    L.append(f"          chunks: {', '.join(fd['chunks'])}")
            if cmp.get('os_warning'):
                w = cmp['os_warning']
                L.append(f"        warning ({cmp['runs']}): os-side records differ at {w['kind']}: {w['a']} / {w['b']}")
        if c.get('reason'):
            L.append('        ' + c['reason'])
        if c.get('vacuous'):
            L.append('        ' + c['vacuous'])
        if c.get('detail'):
            L.append('        ' + c['detail'].replace('\n', '\n        '))
    L.append(f"  observations compared per run pair: {tot.get('ticks', 0)} ticks, {tot.get('rng_draws', 0)} RNG draws, "
             f"{tot.get('state_hashes', 0)} state hashes, {tot.get('chunk_hashes', 0)} chunk hashes, "
             f"{tot.get('commands', 0)} commands")
    if rep['mutants']:
        L.append('')
        L.append('SELF-TEST (known-bad oracles must be detected by the core projection)')
        for m in rep['mutants']:
            L.append(f"  {m['verdict']:9s} {m['mutant']:16s} {m['what']}" + (f"  [{m['reason']}]" if m.get('reason') else ''))
            fd = m.get('first_divergence')
            if fd:
                L.append(f"            first divergence at tick {fd['tick']} ({fd['kind']}): {fd['a']}  |  {fd['b']}")
                if fd.get('chunks'):
                    L.append(f"            chunks: {', '.join(fd['chunks'])}")
    L.append('')
    L.append(f"VERDICT: {rep['verdict']}" + (f"  (failures: {', '.join(rep['failures'])})" if rep['failures'] else ''))
    return '\n'.join(L) + '\n'


if __name__ == '__main__':
    sys.exit(main())
