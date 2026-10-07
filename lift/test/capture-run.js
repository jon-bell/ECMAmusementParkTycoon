#!/usr/bin/env node
'use strict';
// Lift run with register capture over ticks A..B (lift side of oracle RCTHOOK_SPIKE=istep=A:B,regs).
//
//   /usr/bin/nodejs lift/test/capture-run.js --script S --out DIR --ticks A:B [--lift out/lift-ref]
//   python3 tools/stepdiff.py diff ORACLE_RUN/istep_regs.bin DIR/lift_regs.bin
//
// Wraps the host's tick hook: capture starts in the hook of tick A (after the host's tick
// bookkeeping, so the T record precedes the tick's game code as in the oracle) and stops in the
// hook of tick B+1. Ticks are counted as the host counts them (its counter resets at a load).
// A debugging driver: the HOST is asked to offer the same through RCTHOOK_SPIKE.

const path = require('path');
const fs = require('fs');
const rt = require('../runtime');
const capture = require('../runtime/capture');

const ROOT = path.join(__dirname, '../..');
const o = { lift: path.join(ROOT, 'out/lift-ref') };
const av = process.argv.slice(2);
for (let k = 0; k < av.length; k++) {
  if (av[k] === '--script') o.script = av[++k];
  else if (av[k] === '--out') o.out = av[++k];
  else if (av[k] === '--ticks') { const [a, b] = av[++k].split(':').map(Number); o.a = a; o.b = b; }
  else if (av[k] === '--lift') o.lift = av[++k];
  else if (av[k] === '--os-replay') o.replay = av[++k];
}
// --os-replay ORACLE_CAPTURE (diagnostic only, never for a gate): after every host call made while
// capturing, set ecx, edx and eflags (and eax after a void import, per apisig) to the values the
// oracle's after-OS record holds, so that stepdiff tests the lifted code beyond OS calls whose
// register leftovers the host does not model. The k-th host call pairs with the k-th after-OS R.
function readAfterOs(file) {
  const b = fs.readFileSync(file), out = [];
  for (let p = 16; p < b.length;) {
    const t = b.readUInt32LE(p) & 0xFF;
    if (t === 0x52) { if ((b.readUInt32LE(p) >>> 8) & 2) out.push([2, 3, 4, 5, 10].map((j) => b.readUInt32LE(p + 4 * j)).concat([b.readUInt32LE(p + 4)])); p += 44; }
    else if (t === 0x57 || t === 0x4F) p += 12; else if (t === 0x54) p += 8; else throw new Error('bad record');
  }
  return out;   // [eax, ecx, edx, ebx, eflags, eip]
}
fs.mkdirSync(o.out, { recursive: true });
const m = rt.createMachine({ exePath: path.join(ROOT, 'game/cd/English/rct.exe'), liftDir: o.lift });
const host = require('../host').attach(m, { exePath: path.join(ROOT, 'game/cd/English/rct.exe'), scriptPath: o.script, outDir: o.out, rt });
const TICK = 0x43888E;
const orig = m.hooks.get(TICK);
const mapBlocks = new Set(JSON.parse(fs.readFileSync(path.join(ROOT, 'out/spikes/s1v4/cfg.json'), 'utf8')).blocks);
let cap = null, counts = null;
m.hooks.set(TICK, (mm) => {
  const r = orig(mm);
  const t = host.hooks ? host.hooks.tick : undefined;
  const tick = t !== undefined ? t : (mm._capTick = (mm._capTick || 0) + 1);
  if (cap === null && counts === null && tick === o.a) cap = capture.start(mm, path.join(o.out, 'lift_regs.bin'), { mapBlocks });
  if (cap !== null) {
    if (tick > o.b) { counts = cap.stop(); cap = null; } else cap.tick(tick);
  }
  return r;
});
if (o.replay) {
  const after = readAfterOs(o.replay);
  const voids = new Set(JSON.parse(fs.readFileSync(path.join(ROOT, 'out/lift-capture/void_slots.json'), 'utf8')));
  let k = 0, replayed = 0;
  m.hostTable = m.hostTable.map((impl, idx) => impl && ((mm) => {
    const slot = mm.xslot;
    impl(mm);
    if (mm.capture === null || k >= after.length) return;
    const a = after[k++];
    if (a[5] !== mm.eip) throw new Error(`os-replay: host call ${k} returns to ${mm.eip.toString(16)}, oracle to ${a[5].toString(16)}`);
    mm.ecx = a[1]; mm.edx = a[2];
    const f = mm.getEflags(); mm.setEflags((f & ~0xCD5) | (a[4] & 0xCD5));
    if (voids.has(slot)) mm.eax = a[0];
    replayed++;
  }));
  process.on('exit', () => process.stderr.write(`os-replay: ${replayed} host calls replayed\n`));
}
let res = {};
try { m.run(); } catch (e) { res = e instanceof rt.GuestExit ? { exit: e.code } : { error: e }; }
if (cap !== null) counts = cap.stop();
if (host.finish) host.finish(res);
process.stderr.write(`capture ticks ${o.a}..${o.b}: ${JSON.stringify(counts)}${res.error ? ' stopped: ' + res.error.message : ''}\n`);
