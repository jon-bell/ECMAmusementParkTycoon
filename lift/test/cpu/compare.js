#!/usr/bin/env node
'use strict';
// Compare the single-instruction lift with native results (lift/test/cpu/README.md).
//
//   /usr/bin/nodejs lift/test/cpu/compare.js <test-dir> <single-lift-dir> [--max-examples N] [--json out.json]
//
// For every test: set the machine to the test's input state (registers, EFLAGS with TF set as
// natively, memory regions, the 12-byte IRET frame the harness leaves below esp), run the
// lifted instruction, and compare with the native outcome:
//   - native single-step trap: registers, eip, CF PF AF ZF SF OF DF, region bytes (stack-scratch
//     bytes below the final esp are excluded: Wine writes its exception frame there);
//   - native access violation: the lift must raise GuestFault;
//   - native #DE: the lift must raise GuestException DE and leave every register unchanged.
// Prints counts per instruction form and mismatch kind; exit status 1 if any mismatch.

const fs = require('fs');
const path = require('path');
const rt = require('../../runtime');

const SCR = 0x02000000, STK = 0x02100000, STK_HI = 0x02400000, SYN = 0x02800000;
const REGS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
const FLAGS = [['cf', 0], ['pf', 2], ['af', 4], ['zf', 6], ['sf', 7], ['df', 10], ['of', 11]];
const CODE = { 0x80000004: 'step', 0xC0000005: 'av', 0xC0000094: 'de', 0xC0000095: 'de', 0xFFFFFFFF: 'native-crash' };

function main() {
  const args = process.argv.slice(2);
  const dir = args[0], liftDir = args[1];
  let maxEx = 3, jsonOut = null;
  for (let k = 2; k < args.length; k++) {
    if (args[k] === '--max-examples') maxEx = +args[++k];
    else if (args[k] === '--json') jsonOut = args[++k];
  }
  const forms = JSON.parse(fs.readFileSync(path.join(dir, 'forms.json'), 'utf8'));
  const T = fs.readFileSync(path.join(dir, 'tests.bin'));
  const R = fs.readFileSync(path.join(dir, 'results.bin'));
  if (T.toString('latin1', 0, 4) !== 'CPT1' || R.readUInt32LE(0) !== 0x31525043) throw new Error('bad files');
  const n = T.readUInt32LE(4), cs = R.readUInt32LE(8);
  if (R.readUInt32LE(4) !== n) throw new Error('results count mismatch');

  // machine: image (IAT = host addresses), scratch mapped like the harness
  const m = rt.createMachine({ exePath: path.join(__dirname, '../../../game/cd/English/rct.exe') });
  rt.mapPages(SCR, 0x100000, rt.PROT_RW);
  rt.mapPages(STK, STK_HI - STK, rt.PROT_RW);
  rt.mapPages(SYN, 0x100000, rt.PROT_R | rt.PROT_CODE);
  const fns = new Map();
  const man = JSON.parse(fs.readFileSync(path.join(liftDir, 'manifest.json'), 'utf8'));
  const ops = require('../../runtime/ops');
  for (const f of man.files) require(path.resolve(liftDir, f))(ops, (a, ni, fn) => fns.set(a, fn));

  const stats = new Map();   // form -> {n, ok, kinds: Map(kind -> count), ex: []}
  let tp = 8, rp = 16, total = 0, bad = 0, skipped = 0;
  const nf = 7;
  for (let t = 0; t < n; t++) {
    // ---- parse test
    const addr = T.readUInt32LE(tp), tflags = T.readUInt32LE(tp + 4);
    const regsIn = REGS.map((_, k) => T.readUInt32LE(tp + 8 + 4 * k));
    const efl = T.readUInt32LE(tp + 40);
    const nc = T.readUInt32LE(tp + 44);
    let p = tp + 48 + ((nc + 3) & ~3);
    const nr = T.readUInt32LE(p); p += 4;
    const regions = [];
    for (let k = 0; k < nr; k++) {
      const a = T.readUInt32LE(p), len = T.readUInt32LE(p + 4), ro = T.readUInt32LE(p + 8);
      regions.push({ a, len, ro, data: T.subarray(p + 12, p + 12 + len) });
      p += 12 + ((len + 3) & ~3);
    }
    tp = p;
    // ---- parse native result
    const code = R.readUInt32LE(rp), faddr = R.readUInt32LE(rp + 4);
    const out = REGS.map((_, k) => R.readUInt32LE(rp + 8 + 4 * k));
    const eipOut = R.readUInt32LE(rp + 40), eflOut = R.readUInt32LE(rp + 44);
    let q = rp + 48;
    const after = [];
    for (const r of regions) { after.push(R.subarray(q, q + r.len)); q += (r.len + 3) & ~3; }
    rp = q;

    const fkey = (forms[addr] || '?|?').split('|')[0];
    let st = stats.get(fkey);
    if (!st) { st = { n: 0, ok: 0, kinds: new Map(), ex: [] }; stats.set(fkey, st); }
    const fn = fns.get(addr);
    const kind = CODE[code] || ('code' + code.toString(16));
    if (!fn) { skipped++; continue; }
    if (kind === 'native-crash') { st.n++; note(st, 'native-crash', { t, addr }); bad++; continue; }
    total++; st.n++;

    // ---- set up JS state
    for (const r of regions) if (!r.ro) rt.mem.set(r.data, r.a);
    REGS.forEach((r, k) => { m[r] = regsIn[k]; });
    m.setEflags(efl | 0x302);
    const esp = regsIn[4];
    rt.dv.setUint32(esp - 12, addr, true); rt.dv.setUint32(esp - 8, cs, true); rt.dv.setUint32(esp - 4, efl | 0x302, true);
    for (const r of regions) if (!r.ro) {     // the frame lies inside a declared region: keep its bytes as natively
      for (let b = Math.max(r.a, esp - 12); b < Math.min(r.a + r.len, esp); b++) { /* already written above */ }
    }
    m.eip = addr;
    let js = null, err = null;
    try { js = fn(m) >>> 0; } catch (e) { err = e; }

    const diffs = [];
    if (kind === 'step') {
      if (err) diffs.push('js-threw:' + err.name);
      else {
        REGS.forEach((r, k) => { if (m[r] !== out[k]) diffs.push(r); });
        if (js !== eipOut) diffs.push('eip');
        const fe = m.getEflags();
        for (const [f, b] of FLAGS) if (((fe >>> b) & 1) !== ((eflOut >>> b) & 1)) diffs.push(f);
        const espOut = out[4];
        regions.forEach((r, k) => {
          const A = after[k];
          for (let b = 0; b < r.len; b++) {
            const ad = r.a + b;
            if (ad >= STK && ad < STK_HI && ad < espOut) continue;
            if (rt.mem[ad] !== A[b]) { diffs.push('mem'); break; }
          }
        });
      }
    } else if (kind === 'av') {
      if (!(err instanceof rt.GuestFault)) diffs.push('js-no-fault' + (err ? ':' + err.name : ''));
    } else if (kind === 'de') {
      if (!(err && err.name === 'GuestException' && err.kind === 'DE')) diffs.push('js-no-DE' + (err ? ':' + err.name : ''));
      else REGS.forEach((r, k) => { if (m[r] !== regsIn[k]) diffs.push('de-' + r); });
    } else diffs.push('native-' + kind);
    // restore the native post-state so later tests see the same memory on both sides
    regions.forEach((r, k) => { if (!r.ro) rt.mem.set(after[k], r.a); });

    if (diffs.length === 0) { st.ok++; continue; }
    bad++;
    for (const d of new Set(diffs)) {
      note(st, d, null);
    }
    if (st.ex.length < maxEx) {
      st.ex.push({
        t, addr: hex(addr), kind, diffs, in: Object.fromEntries(REGS.map((r, k) => [r, hex(regsIn[k])])), eflIn: hex(efl),
        native: Object.fromEntries(REGS.map((r, k) => [r, hex(out[k])])), nEip: hex(eipOut), nEfl: hex(eflOut),
        js: err ? String(err.message) : { ...Object.fromEntries(REGS.map((r) => [r, hex(m[r])])), eip: hex(js), efl: hex(m.getEflags()) },
        faddr: hex(faddr),
      });
    }
  }
  // ---- report
  const rows = [...stats.entries()].sort((a, b) => (b[1].n - b[1].ok) - (a[1].n - a[1].ok));
  let nbadForms = 0;
  for (const [k, s] of rows) {
    if (s.ok === s.n) continue;
    nbadForms++;
    console.log(`${k.padEnd(28)} ${String(s.n - s.ok).padStart(6)}/${String(s.n).padEnd(6)} ` +
      [...s.kinds.entries()].map(([d, c]) => `${d}:${c}`).join(' '));
  }
  console.log(`\n${total} tests compared (${skipped} without a lifted function), ${total - bad >= 0 ? total - bad : 0} identical, ` +
    `${bad} differing, forms: ${stats.size} (${nbadForms} with differences)`);
  if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(Object.fromEntries(rows.filter(([, s]) => s.ok !== s.n).map(([k, s]) =>
    [k, { n: s.n, bad: s.n - s.ok, kinds: Object.fromEntries(s.kinds), ex: s.ex }])), null, 1));
  process.exitCode = bad || total === 0 ? 1 : 0;
}
function note(st, d) { st.kinds.set(d, (st.kinds.get(d) || 0) + 1); }
function hex(v) { return '0x' + (v >>> 0).toString(16); }

main();
