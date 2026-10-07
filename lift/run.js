#!/usr/bin/env node
'use strict';
// Run the lifted rct.exe.
//
//   node lift/run.js --exe <rct.exe> --game <dir> --script <s> --out <dir> [--lift out/lift]
//                    [--instrument] [--no-host] [--coverage FILE [--coverage-split-frame N]]
//                    [--host-mutant NAME]
//
// --coverage FILE: record the set of executed block starts (uint32 LE, ascending) into FILE.
//   Opt-in: it runs the instrumented loop (one function per block, no regions; about 2x slower).
//   With --coverage-split-frame N, FILE.since-frameN.bin also gets the blocks executed from the
//   N-th frame entry (0x4385D8) on: the oracle's cover instrument arms breakpoints in the
//   checksummed range only from frame 2 (oracle/spike.c), so the gate compares like with like.
// --host-mutant NAME: a known-bad host for the Stage 1 gate's self-test (tools/gate_lift.py),
//   wrapping the host's bound imports after it attaches (the host itself is not modified):
//     clock-2ms       WINMM!timeGetTime advances the virtual clock by 2 ms per query
//     systime-plus-1d KERNEL32!GetSystemTime answers one day later
//
// The host (lift/host/index.js) is attached through one function:
//   attach(m, {exePath, gameDir, scriptPath, outDir, rt}) -> host
// where host may have finish({exit?, error?}) -> exit status (number), called once at the end.
// Without a host (or --no-host) every import is unbound and the run stops at the first host
// call with HostMissing, naming it.

const fs = require('fs');
const path = require('path');
const rt = require('./runtime');

function parseArgs(argv) {
  const o = { lift: path.join(__dirname, '../out/lift') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--exe') o.exe = val();
    else if (a === '--game') o.game = val();
    else if (a === '--script') o.script = val();
    else if (a === '--out') o.out = val();
    else if (a === '--lift') o.lift = val();
    else if (a === '--instrument') o.instrument = true;
    else if (a === '--no-host') o.noHost = true;
    else if (a === '--coverage') o.coverage = val();
    else if (a === '--coverage-split-frame') o.coverageSplit = Number(val());
    else if (a === '--host-mutant') o.hostMutant = val();
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.exe) throw new Error('--exe is required');
  return o;
}

function describeState(m) {
  const r = m.regs();
  const h = (v) => rt.hex(v);
  return `eip=${h(r.eip)} eax=${h(r.eax)} ebx=${h(r.ebx)} ecx=${h(r.ecx)} edx=${h(r.edx)} ` +
    `esi=${h(r.esi)} edi=${h(r.edi)} ebp=${h(r.ebp)} esp=${h(r.esp)} eflags=${h(r.eflags)} depth=${m.depth}`;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.out) fs.mkdirSync(o.out, { recursive: true });
  const t0 = process.hrtime.bigint();
  const m = rt.createMachine({ exePath: o.exe, liftDir: o.lift });
  const tLoad = Number(process.hrtime.bigint() - t0) / 1e9;
  if (o.instrument || o.coverage) m.enableInstrumentation({ coverage: !!o.coverage });
  let host = null;
  const hostIndex = path.join(__dirname, 'host', 'index.js');
  if (!o.noHost && fs.existsSync(hostIndex)) {
    host = require(hostIndex).attach(m, { exePath: o.exe, gameDir: o.game, scriptPath: o.script, outDir: o.out, rt });
  }
  if (o.hostMutant) applyHostMutant(m, host, o.hostMutant);
  const cov = o.coverage ? coverageRecorder(m, o.coverageSplit) : null;
  let status = 0, result = {};
  const t1 = process.hrtime.bigint();
  try {
    m.run();
    result = { error: new Error('top-level run returned (HOST_RETURN at depth 0)') };
  } catch (e) {
    result = e instanceof rt.GuestExit ? { exit: e.code } : { error: e };
  }
  const secs = Number(process.hrtime.bigint() - t1) / 1e9;
  if (result.error) {
    const e = result.error;
    process.stderr.write(`lift run stopped: ${e.message}\n  ${describeState(m)}\n`);
    if (!(e instanceof rt.MissingBlock || e instanceof rt.HostMissing || e instanceof rt.GuestFault ||
      e instanceof rt.GuestException)) process.stderr.write(e.stack + '\n');
    status = 1;
  }
  if (host && host.finish) {
    const s = host.finish(result);
    if (typeof s === 'number') status = s;
  }
  const stats = { load_s: tLoad, run_s: secs, host_calls: m.hostCalls };
  if (o.hostMutant) stats.host_mutant = o.hostMutant;
  if (cov) Object.assign(stats, cov.write(o.coverage));
  if (o.instrument) Object.assign(stats, { blocks: m.blockCount, insns: m.insnCount, insns_per_s: Math.round(m.insnCount / secs) });
  process.stderr.write(`lift run: ${JSON.stringify(stats)}${result.exit !== undefined ? ' exit=' + result.exit : ''}\n`);
  if (o.out) fs.writeFileSync(path.join(o.out, 'lift-run.json'), JSON.stringify({ ...stats, exit: result.exit, error: result.error ? result.error.message : undefined }, null, 1));
  process.exitCode = status;
}

// Known-bad hosts (principle 6): wrap a bound import implementation. Never used by a clean run.
function applyHostMutant(m, host, name) {
  const wrap = (key, mk) => {
    const im = m.importByKey.get(key);
    if (!im || !m.hostTable[im.index]) throw new Error(`host mutant ${name}: ${key} is not bound`);
    m.hostTable[im.index] = mk(m.hostTable[im.index]);
  };
  if (name === 'clock-2ms') {
    if (!host || !host.clock) throw new Error('host mutant clock-2ms: the host has no virtual clock');
    // the host returned the clock and advanced it by the pinned quantum; make the step 2 ms
    wrap('WINMM.DLL!timeGetTime', (orig) => (mm) => { orig(mm); host.clock.vt = (mm.eax + 2) >>> 0; });
  } else if (name === 'systime-plus-1d') {
    wrap('KERNEL32.DLL!GetSystemTime', (orig) => (mm) => {
      const p = mm.arg(0);
      orig(mm);
      const w = (k) => rt.dv.getUint16(p + 2 * k, true);
      const d = new Date(Date.UTC(w(0), w(1) - 1, w(3), w(4), w(5), w(6), w(7)) + 86400000);
      const out = [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDay(), d.getUTCDate(),
        d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds()];
      out.forEach((v, k) => rt.dv.setUint16(p + 2 * k, v, true));
    });
  } else throw new Error(`unknown host mutant ${name}`);
  process.stderr.write(`lift run: HOST MUTANT ${name} active (known-bad host, gate self-test only)\n`);
}

// Executed block starts (opt-in, instrumented loop). m.coverage is a byte per image offset,
// set at every executed block start.
const A_FRAME = 0x4385D8;
function coverageRecorder(m, splitFrame) {
  let pre = null, frames = 0;
  if (splitFrame) {
    const orig = m.hooks.get(A_FRAME);
    m.hooks.set(A_FRAME, (mm) => {
      if (++frames === splitFrame) { pre = m.coverage.slice(); m.coverage.fill(0); }
      return orig ? orig(mm) : undefined;
    });
  }
  const list = (bits) => {
    const a = [];
    for (let i = 0; i < bits.length; i++) if (bits[i]) a.push(rt.IMAGE_LO + i);
    return Buffer.from(new Uint32Array(a).buffer);
  };
  return {
    write(file) {
      const cur = m.coverage, all = pre ? cur.map((v, i) => v | pre[i]) : cur;
      const buf = list(all);
      fs.writeFileSync(file, buf);
      const r = { coverage_blocks: buf.length / 4 };
      if (splitFrame) {
        // before the split frame is reached, nothing counts as "since" it
        const since = pre ? list(cur) : Buffer.alloc(0);
        fs.writeFileSync(`${file}.since-frame${splitFrame}.bin`, since);
        r.coverage_split_frame = splitFrame; r.coverage_blocks_since_split = since.length / 4;
      }
      return r;
    },
  };
}

main();
