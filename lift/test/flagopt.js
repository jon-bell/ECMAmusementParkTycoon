#!/usr/bin/env node
'use strict';
// Self-check of the flag-liveness optimisation: every block of the optimised lift against the
// same block of the reference lift (--no-flag-opt), on random states.
//
//   /usr/bin/nodejs lift/test/flagopt.js <opt-lift-dir> <ref-lift-dir> [--states N] [--seed S] [--mutant]
//
// Per block and state: same exception (or none), same next eip, same registers, same sequence of
// guest stores, and the same value of every flag the successor block needs (livein.json; all six
// flags when the successor is not a lifted block). Exits 1 on any difference.
// --mutant flips CF before comparing, to prove the check can fail (principle 6).

const fs = require('fs');
const path = require('path');
const rt = require('../runtime');
const M = require('../runtime/memory');

const args = process.argv.slice(2);
const optDir = args[0], refDir = args[1];
let N = 3, seed = 1, mutant = false;
for (let k = 2; k < args.length; k++) {
  if (args[k] === '--states') N = +args[++k]; else if (args[k] === '--seed') seed = +args[++k]; else if (args[k] === '--mutant') mutant = true;
}
let rs = seed >>> 0 || 1;
const rnd = () => { rs ^= rs << 13; rs >>>= 0; rs ^= rs >>> 17; rs ^= rs << 5; rs >>>= 0; return rs; };

const m = rt.createMachine({ exePath: path.join(__dirname, '../../game/cd/English/rct.exe') });
const SCR = 0x02000000, SCR_N = 0x01000000;
rt.mapPages(SCR, SCR_N, rt.PROT_RW);
for (let a = SCR; a < SCR + SCR_N; a += 4) rt.dv.setUint32(a, rnd(), true);
const snapshot = rt.mem.slice();

function load(dir) {
  const fns = new Map();
  const man = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const ops = require('../runtime/ops');
  for (const f of man.files) require(path.resolve(dir, f))(ops, (a, n, fn) => fns.set(a, fn));
  return fns;
}
const OPT = load(optDir), REF = load(refDir);
const livein = JSON.parse(fs.readFileSync(path.join(optDir, 'livein.json'), 'utf8'));
const LIVE = new Map(Object.entries(livein).map(([k, v]) => [Number(k), v]));
const FL = { c: 'cf', p: 'pf', a: 'af', z: 'zf', s: 'sf', o: 'of' };

let log = [];
M.setWriteLog((size, a, v) => log.push(size, a, v));
const SPECIAL = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF];
const REGS = ['eax', 'ecx', 'edx', 'ebx', 'ebp', 'esi', 'edi'];

function state() {
  const s = {};
  for (const r of REGS) {
    const x = rnd() % 10;
    s[r] = x < 5 ? (SCR + 0x100000 + rnd() % (SCR_N - 0x200000)) >>> 0 : x < 7 ? SPECIAL[rnd() % SPECIAL.length] : rnd();
  }
  s.esp = (SCR + 0x800000 + (rnd() % 0x100000) * 4) >>> 0;
  s.efl = rnd() & 0x8D5;
  return s;
}
function run(fn, s) {
  for (const r of REGS) m[r] = s[r];
  m.esp = s.esp; m.setEflags(s.efl | 0x202);
  m.fpu.top = 0; m.fpu.sw = 0; m.fpu.cw = 0x27F;
  log = [];
  let eip, err = null;
  try { eip = fn(m) >>> 0; } catch (e) { err = e.name + ':' + (e.kind || e.op || '') + ':' + (e.addr || e.eip || ''); }
  const out = { eip, err, log, regs: REGS.map((r) => m[r]).concat([m.esp]), fl: { cf: m.cf, pf: m.pf, af: m.af, zf: m.zf, sf: m.sf, of: m.of, df: m.df } };
  // undo the stores
  for (let k = 0; k < log.length; k += 3) for (let b = 0; b < log[k]; b++) rt.mem[log[k + 1] + b] = snapshot[log[k + 1] + b];
  return out;
}

let blocks = 0, runs = 0, bad = 0, faults = 0;
const ex = [];
for (const [a, fo] of OPT) {
  const fr = REF.get(a);
  if (!fr) { bad++; ex.push(`${a.toString(16)}: missing in ref`); continue; }
  blocks++;
  for (let k = 0; k < N; k++) {
    const s = state();
    const A = run(fo, s), B = run(fr, s);
    runs++;
    if (A.err) faults++;
    if (mutant) A.fl.cf ^= 1;
    const d = [];
    if (A.err !== B.err) d.push(`err ${A.err} / ${B.err}`);
    else if (!A.err) {
      if (A.eip !== B.eip) d.push('eip');
      A.regs.forEach((v, i) => { if (v !== B.regs[i]) d.push(REGS.concat(['esp'])[i]); });
      if (A.log.join() !== B.log.join()) d.push('stores');
      const need = LIVE.has(A.eip) ? LIVE.get(A.eip) : 'cpazso';
      for (const f of need) if (A.fl[FL[f]] !== B.fl[FL[f]]) d.push(f + 'f');
      if (A.fl.df !== B.fl.df) d.push('df');
    }
    if (d.length) { bad++; if (ex.length < 20) ex.push(`0x${a.toString(16)} state ${k}: ${d.join(' ')}`); break; }
  }
}
console.log(ex.join('\n'));
console.log(`${blocks} blocks, ${runs} runs (${faults} faulted identically-or-not), ${bad} blocks differ`);
process.exitCode = bad || runs === 0 ? 1 : 0;
