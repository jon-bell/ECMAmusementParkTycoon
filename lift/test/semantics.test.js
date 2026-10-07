'use strict';
// Instruction semantics: hand-computed expectations (Intel SDM; undefined flags as measured on
// the oracle CPU, see lift/runtime/ops.js HW). Each case is an encoded instruction lifted with
// `lifter.py --insns` and run on a given state.
//
//   /usr/bin/nodejs --test lift/test/semantics.test.js
//
// Needs the user's rct.exe (the lifter and runtime load it) and the .venv Python.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const rt = require('../runtime');

const ROOT = path.join(__dirname, '../..');
const EXE = path.join(ROOT, 'game/cd/English/rct.exe');
const OUT = path.join(ROOT, 'out/lift-unit');
const BASE = 0x02800000;
const have = fs.existsSync(EXE);

const F = { cf: 1, pf: 4, af: 0x10, zf: 0x40, sf: 0x80, df: 0x400, of: 0x800 };
const flags = (s) => s.split(/\s+/).filter(Boolean).reduce((v, f) => v | F[f], 0);

// [hex, description, input {regs, fl, mem: {addr: [bytes]}}, expect {regs, fl (exact set of
//  CF PF AF ZF SF OF DF), flMask (only these flags checked), mem: {addr: [bytes]}, eip, exc}]
const C = [];
const add = (hex, what, inp, exp) => C.push({ hex, what, inp, exp });

// ---- ADD/ADC/SUB/SBB/CMP flags at 8/16/32 ----
add('00c8', 'add al,cl 0x7F+1: OF SF AF', { eax: 0x7F, ecx: 1 }, { eax: 0x80, fl: 'of sf af' });
add('00c8', 'add al,cl 0xFF+1: CF ZF AF PF', { eax: 0x12FF, ecx: 1 }, { eax: 0x1200, fl: 'cf zf af pf' });
add('6601c8', 'add ax,cx 0x8000+0x8000: CF OF ZF PF', { eax: 0xAAAA8000, ecx: 0x8000 }, { eax: 0xAAAA0000, fl: 'cf of zf pf' });
add('01c8', 'add eax,ecx 0xFFFFFFFF+1', { eax: 0xFFFFFFFF, ecx: 1 }, { eax: 0, fl: 'cf zf af pf' });
add('11c8', 'adc eax,ecx with CF: 0xFFFFFFFF+0+1', { eax: 0xFFFFFFFF, ecx: 0, fl: 'cf' }, { eax: 0, fl: 'cf zf af pf' });
add('11c8', 'adc eax,ecx 0x7FFFFFFF+0+CF', { eax: 0x7FFFFFFF, ecx: 0, fl: 'cf' }, { eax: 0x80000000, fl: 'of sf af pf' });
add('10e0', 'adc al,ah (high byte source) 0x10+0x20+CF', { eax: 0x2010, fl: 'cf' }, { eax: 0x2031, fl: '' });
add('28c8', 'sub al,cl 0x00-0x01: CF SF AF PF', { eax: 0, ecx: 1 }, { eax: 0xFF, fl: 'cf sf af pf' });
add('28c8', 'sub al,cl 0x80-0x01: OF AF', { eax: 0x80, ecx: 1 }, { eax: 0x7F, fl: 'of af' });
add('19c8', 'sbb eax,ecx 0-0-CF', { eax: 0, ecx: 0, fl: 'cf' }, { eax: 0xFFFFFFFF, fl: 'cf sf af pf' });
add('19c8', 'sbb eax,ecx 5-0xFFFFFFFF-CF', { eax: 5, ecx: 0xFFFFFFFF, fl: 'cf' }, { eax: 5, fl: 'cf pf af' });
add('6619c8', 'sbb ax,cx 0x8000-1-0: OF', { eax: 0x8000, ecx: 1 }, { eax: 0x7FFF, fl: 'of af pf' });
add('38e0', 'cmp al,ah equal (high byte)', { eax: 0x4242 }, { eax: 0x4242, fl: 'zf pf' });
add('6683f9ff', 'cmp cx,-1 (imm8 sign-extended to 16)', { ecx: 0x1234FFFF }, { ecx: 0x1234FFFF, fl: 'zf pf' });
add('3d00000080', 'cmp eax,0x80000000 with eax=0', { eax: 0 }, { fl: 'cf of sf pf' });

// ---- logic ----
add('21c8', 'and eax,ecx: CF OF cleared, AF 0', { eax: 0xF0F0F0F0, ecx: 0x0F0F0F0F, fl: 'cf of af' }, { eax: 0, fl: 'zf pf' });
add('30e4', 'xor ah,ah', { eax: 0x1234FF56, fl: 'cf sf' }, { eax: 0x12340056, fl: 'zf pf' });
add('6685c0', 'test ax,ax negative', { eax: 0x8001 }, { eax: 0x8001, fl: 'sf' });

// ---- INC DEC NEG NOT ----
add('40', 'inc eax keeps CF; 0x7FFFFFFF -> OF', { eax: 0x7FFFFFFF, fl: 'cf' }, { eax: 0x80000000, fl: 'cf of sf af pf' });
add('6648', 'dec ax 0x8000 -> OF AF', { eax: 0x8000 }, { eax: 0x7FFF, fl: 'of af pf' });
add('fec4', 'inc ah 0xFF -> 0 ZF AF', { eax: 0xFF00 }, { eax: 0, fl: 'zf af pf' });
add('f7d8', 'neg eax 0x80000000: CF OF', { eax: 0x80000000 }, { eax: 0x80000000, fl: 'cf of sf pf' });
add('f6dc', 'neg ah 0 -> CF 0', { eax: 0x0000, fl: 'cf' }, { eax: 0, fl: 'zf pf' });
add('f6d4', 'not ah: no flags', { eax: 0x0F00, fl: 'cf' }, { eax: 0xF000, fl: 'cf' });

// ---- shifts/rotates ----
add('c1e000', 'shl eax,0: nothing changes', { eax: 5, fl: 'cf of zf' }, { eax: 5, fl: 'cf of zf' });
add('d3e0', 'shl eax,cl cl=32 (masked to 0): nothing', { eax: 5, ecx: 32, fl: 'cf' }, { eax: 5, fl: 'cf' });
add('d1e0', 'shl eax,1 0x80000000 -> CF ZF OF, AF=1', { eax: 0x80000000 }, { eax: 0, fl: 'cf zf of pf af' });
add('c0e404', 'shl ah,4', { eax: 0x1F00 }, { eax: 0xF000, fl: 'cf sf pf af' });
add('c0e009', 'shl al,9: result 0, CF 0 (count > width)', { eax: 0xFF, fl: 'cf' }, { eax: 0, fl: 'zf pf af' });
add('c0e008', 'shl al,8: CF = bit 0', { eax: 0x01 }, { eax: 0, fl: 'cf zf pf af of' });
add('66c1e810', 'shr ax,16: CF = bit 15', { eax: 0x8000 }, { eax: 0, fl: 'cf zf pf af' });
add('d1e8', 'shr eax,1: OF = old msb', { eax: 0x80000001 }, { eax: 0x40000000, fl: 'cf of pf af' });
add('c1f804', 'sar eax,4 negative', { eax: 0x80000010 }, { eax: 0xF8000001, fl: 'sf af' });
add('c0f80f', 'sar al,15 (count > width): sign fill, CF = sign', { eax: 0x80 }, { eax: 0xFF, fl: 'cf sf pf af' });
add('c0c004', 'rol al,4', { eax: 0x81 }, { eax: 0x18, fl: 'pf', flMask: 'cf of' });
add('c0c008', 'rol al,8: result same, CF = lsb, OF = msb^lsb', { eax: 0x81, fl: '' }, { eax: 0x81, fl: 'cf', flMask: 'cf of' });
add('66c1c810', 'ror ax,16: same, CF = msb', { eax: 0x8001 }, { eax: 0x8001, fl: 'cf of', flMask: 'cf of' });
add('66d1d0', 'rcl ax,1 with CF', { eax: 0x8000, fl: 'cf' }, { eax: 0x0001, fl: 'cf of', flMask: 'cf of' });
add('66c1d011', 'rcl ax,17: no rotation, CF kept', { eax: 0x1234, fl: 'cf' }, { eax: 0x1234, fl: 'cf of', flMask: 'cf of' });
add('c1d802', 'rcr eax,2 with CF', { eax: 0x00000003, fl: 'cf' }, { eax: 0xC0000000, fl: 'cf', flMask: 'cf of' });
add('0facd008', 'shrd eax,edx,8', { eax: 0x12345678, edx: 0xAB }, { eax: 0xAB123456, fl: 'of sf af pf', flMask: 'cf of sf zf pf af' });

// ---- multiply / divide ----
add('f7e3', 'mul ebx 0xFFFFFFFF^2', { eax: 0xFFFFFFFF, ebx: 0xFFFFFFFF }, { eax: 1, edx: 0xFFFFFFFE, fl: 'cf of', flMask: 'cf of' });
add('f7eb', 'imul ebx -1*-1', { eax: 0xFFFFFFFF, ebx: 0xFFFFFFFF }, { eax: 1, edx: 0, fl: '', flMask: 'cf of' });
add('f7eb', 'imul ebx 0x80000000*-1', { eax: 0x80000000, ebx: 0xFFFFFFFF }, { eax: 0x80000000, edx: 0, fl: 'cf of', flMask: 'cf of' });
add('66f7eb', 'imul bx -2*3', { eax: 0xFFFE, ebx: 3, edx: 0xAAAA5555 }, { eax: 0xFFFA, edx: 0xAAAAFFFF, fl: '', flMask: 'cf of' });
add('0fafc3', 'imul eax,ebx overflow', { eax: 0x10000, ebx: 0x10000 }, { eax: 0, fl: 'cf of', flMask: 'cf of' });
add('6bc385', 'imul eax,ebx,-123', { ebx: 2 }, { eax: (-246) >>> 0, fl: '', flMask: 'cf of' });
add('6669c33482', 'imul ax,bx,0x8234 overflow', { eax: 0xFFFF0000, ebx: 2 }, { eax: 0xFFFF0468, fl: 'cf of', flMask: 'cf of' });
add('f7f3', 'div ebx 64-bit dividend', { edx: 1, eax: 0, ebx: 3 }, { eax: 0x55555555, edx: 1, fl: 'af', flMask: 'pf af zf sf' });
add('f7f3', 'div ebx by zero -> #DE, state unchanged', { edx: 0, eax: 5, ebx: 0 }, { exc: 'DE', eax: 5 });
add('f7f3', 'div ebx quotient overflow -> #DE', { edx: 3, eax: 0, ebx: 3 }, { exc: 'DE', edx: 3 });
add('f7fb', 'idiv ebx -2^31 / -1 -> #DE', { edx: 0xFFFFFFFF, eax: 0x80000000, ebx: 0xFFFFFFFF }, { exc: 'DE' });
add('f7fb', 'idiv ebx -7/2 = -3 r -1', { edx: 0xFFFFFFFF, eax: (-7) >>> 0, ebx: 2 }, { eax: (-3) >>> 0, edx: 0xFFFFFFFF });
add('66f7fb', 'idiv bx -32768*2... dx:ax=0xFFFF0000/2', { edx: 0xFFFF, eax: 0, ebx: 2 }, { eax: 0x8000, edx: 0 });
add('f6f7', 'div bh: ax / bh', { eax: 0x0107, ebx: 0x0200 }, { eax: 0x0183 });

// ---- bit tests (memory forms address beyond the operand) ----
add('0fa30b', 'bt [ebx],ecx ecx=35 -> bit 3 of the next dword', { ebx: 0x02000100, ecx: 35, mem: { 0x02000104: [0x08] } }, { fl: 'cf', flMask: 'cf' });
add('0fab0b', 'bts [ebx],ecx ecx=-1 -> bit 31 of the previous dword', { ebx: 0x02000100, ecx: 0xFFFFFFFF, mem: { 0x020000FC: [0, 0, 0, 0] } },
  { fl: '', flMask: 'cf', mem: { 0x020000FC: [0, 0, 0, 0x80] } });
add('660fb30b', 'btr word [ebx],cx cx=-17 -> bit 15 of word at ebx-4', { ebx: 0x02000100, ecx: 0xAAAAFFEF, mem: { 0x020000FC: [0xFF, 0xFF] } },
  { fl: 'cf', flMask: 'cf', mem: { 0x020000FC: [0xFF, 0x7F] } });
add('0fbae025', 'bt eax,37 -> bit 5', { eax: 0x20, fl: 'zf' }, { fl: 'cf zf', flMask: 'cf zf' });
add('0fbcc3', 'bsf eax,ebx zero source: ZF, eax unchanged', { eax: 0x1234, ebx: 0 }, { eax: 0x1234, fl: 'zf', flMask: 'zf' });
add('0fbcc3', 'bsf eax,ebx', { ebx: 0x80000000, fl: 'zf' }, { eax: 31, fl: '', flMask: 'zf' });

// ---- string ops ----
add('f3a4', 'rep movsb overlapping forward (pattern fill)', { esi: 0x02000200, edi: 0x02000201, ecx: 4, mem: { 0x02000200: [7, 1, 2, 3, 4] } },
  { esi: 0x02000204, edi: 0x02000205, ecx: 0, mem: { 0x02000200: [7, 7, 7, 7, 7] } });
add('f3a5', 'rep movsd backwards (DF=1)', { esi: 0x02000208, edi: 0x02000308, ecx: 2, fl: 'df', mem: { 0x02000204: [1, 2, 3, 4, 5, 6, 7, 8] } },
  { esi: 0x02000200, edi: 0x02000300, ecx: 0, mem: { 0x02000304: [1, 2, 3, 4, 5, 6, 7, 8] } });
add('f3ab', 'rep stosd ecx=0: nothing', { edi: 0x02000400, ecx: 0, eax: 0x11223344 }, { edi: 0x02000400, mem: { 0x02000400: [0, 0, 0, 0] } });
add('f2ae', 'repne scasb finds NUL', { edi: 0x02000500, ecx: 0xFFFFFFFF, eax: 0, mem: { 0x02000500: [0x41, 0x42, 0] } },
  { edi: 0x02000503, ecx: 0xFFFFFFFC, fl: 'zf pf', flMask: 'zf cf' });
add('f2ae', 'repne scasb ecx=0: flags unchanged', { edi: 0x02000500, ecx: 0, eax: 0, fl: 'cf sf' }, { edi: 0x02000500, fl: 'cf sf' });
add('66ab', 'stosw DF=1', { edi: 0x02000600, eax: 0xBEEF, fl: 'df' }, { edi: 0x020005FE, mem: { 0x02000600: [0xEF, 0xBE] } });

// ---- stack, control ----
add('60', 'pushad stores the original esp', { esp: 0x02300000, eax: 1, ecx: 2, edx: 3, ebx: 4, ebp: 6, esi: 7, edi: 8 },
  { esp: 0x022FFFE0, mem: { 0x022FFFE0: [8, 0, 0, 0, 7, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0x30, 0x02, 4, 0, 0, 0] } });
add('61', 'popad skips esp', { esp: 0x02300000, mem: { 0x02300000: [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x99, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0] } },
  { esp: 0x02300020, edi: 1, esi: 2, ebp: 3, ebx: 5, edx: 6, ecx: 7, eax: 8 });
add('669c', 'pushf (16-bit) pushes FLAGS with IF and bit 1', { esp: 0x02300000, fl: 'cf zf of df' },
  { esp: 0x022FFFFE, mem: { 0x022FFFFE: [0x43, 0x0E] } });
add('669d', 'popf (16-bit) loads flags, esp+2', { esp: 0x02300000, mem: { 0x02300000: [0xD5, 0x08] } },
  { esp: 0x02300002, fl: 'cf pf af zf sf of' });
add('c9', 'leave', { ebp: 0x02300010, esp: 0x02300000, mem: { 0x02300010: [0x44, 0x33, 0x22, 0x11] } }, { esp: 0x02300014, ebp: 0x11223344 });
add('8f442404', 'pop [esp+4]: address computed after the increment', { esp: 0x02300000, mem: { 0x02300000: [0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] } },
  { esp: 0x02300004, mem: { 0x02300008: [0xAA, 0, 0, 0] } });
add('ff742404', 'push [esp+4]: operand read before the decrement', { esp: 0x02300000, mem: { 0x02300004: [0x5A, 0, 0, 0] } },
  { esp: 0x022FFFFC, mem: { 0x022FFFFC: [0x5A, 0, 0, 0] } });
add('99', 'cdq', { eax: 0x80000000, edx: 0 }, { edx: 0xFFFFFFFF });
add('67e210', 'loop with 0x67: counts in cx only', { ecx: 0xABCD0001 }, { ecx: 0xABCD0000, rel: 3 });
add('e210', 'loop: ecx 0 -> 0xFFFFFFFF, taken', { ecx: 0 }, { ecx: 0xFFFFFFFF, rel: 0x12 });
add('67e310', 'jcxz tests cx only', { ecx: 0x10000 }, { rel: 0x13 });
add('e310', 'jecxz', { ecx: 0x10000 }, { rel: 2 });
add('7c10', 'jl taken when SF != OF', { fl: 'of' }, { rel: 0x12 });
add('0f9fc0', 'setg al (ZF=0, SF=OF)', { eax: 0xFFFFFF00, fl: 'sf of' }, { eax: 0xFFFFFF01 });
add('86c4', 'xchg ah,al', { eax: 0x1234 }, { eax: 0x3412 });
add('660fbec4', 'movsx ax,ah', { eax: 0x8000 }, { eax: 0xFF80 });
add('64a100000000', 'mov eax,fs:[0] reads the TEB', {}, { eax: 0xFFFFFFFF });
add('cc', 'int3 -> GuestException BP', {}, { exc: 'BP' });
add('0fa2', 'cpuid leaf 1: oracle CPU, MMX bit', { eax: 1 }, { eax: 0x00830F10, edx: 0x178BFBFF });

function liftCases() {
  fs.mkdirSync(OUT, { recursive: true });
  const list = C.map((c, k) => ({ addr: BASE + 16 * k, hex: c.hex }));
  fs.writeFileSync(path.join(OUT, 'insns.json'), JSON.stringify(list));
  cp.execFileSync(path.join(ROOT, '.venv/bin/python'), [path.join(ROOT, 'lift/lifter.py'), '--insns', path.join(OUT, 'insns.json'),
    '--out', OUT, '--files', '1'], { cwd: ROOT, stdio: 'pipe' });
  const fns = new Map();
  require(path.join(OUT, 'blocks-00.js'))(require('../runtime/ops'), (a, n, fn) => fns.set(a, fn));
  return fns;
}

test('instruction semantics (hand-computed)', { skip: !have }, () => {
  const fns = liftCases();
  const m = rt.createMachine({ exePath: EXE });
  rt.mapPages(0x02000000, 0x100000, rt.PROT_RW);
  rt.mapPages(0x02100000, 0x300000, rt.PROT_RW);
  const fails = [];
  C.forEach((c, k) => {
    const addr = BASE + 16 * k;
    for (const r of ['eax', 'ecx', 'edx', 'ebx', 'ebp', 'esi', 'edi']) m[r] = 0;
    m.esp = 0x02300000;
    m.setEflags(flags(c.inp.fl || ''));
    for (const [r, v] of Object.entries(c.inp)) if (r !== 'fl' && r !== 'mem') m[r] = v >>> 0;
    rt.mem.fill(0, 0x02000000, 0x02001000);
    rt.mem.fill(0, 0x022FF000, 0x02301000);
    for (const [a, bytes] of Object.entries(c.inp.mem || {})) rt.mem.set(bytes, Number(a));
    const before = m.regs();
    let eip, err;
    try { eip = c.exp.exc ? undefined : fns.get(addr)(m); if (c.exp.exc) fns.get(addr)(m); } catch (e) { err = e; }
    const bad = [];
    if (c.exp.exc) {
      if (!err || err.kind !== c.exp.exc) bad.push(`expected ${c.exp.exc}, got ${err ? err.message : 'none'}`);
      else if (m.eip !== addr) bad.push('exception eip');
      const after = m.regs();
      for (const r of ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']) if (after[r] !== before[r]) bad.push(`${r} changed`);
    } else if (err) bad.push('threw ' + err.message);
    else {
      for (const [r, v] of Object.entries(c.exp)) {
        if (['fl', 'flMask', 'mem', 'rel', 'exc'].includes(r)) continue;
        if (m[r] !== (v >>> 0)) bad.push(`${r}=${hx(m[r])} want ${hx(v)}`);
      }
      if (c.exp.fl !== undefined) {
        const mask = c.exp.flMask ? flags(c.exp.flMask) : 0xCD5;
        const got = m.getEflags() & mask, want = flags(c.exp.fl) & mask;
        if (got !== want) bad.push(`flags ${hx(got)} want ${hx(want)} (mask ${hx(mask)})`);
      }
      for (const [a, bytes] of Object.entries(c.exp.mem || {})) {
        const got = [...rt.mem.subarray(Number(a), Number(a) + bytes.length)];
        if (got.join() !== bytes.join()) bad.push(`mem ${hx(Number(a))} = ${got} want ${bytes}`);
      }
      if (c.exp.rel !== undefined && eip !== addr + c.exp.rel) bad.push(`eip ${hx(eip)} want ${hx(addr + c.exp.rel)}`);
    }
    if (bad.length) fails.push(`${c.hex} ${c.what}: ${bad.join('; ')}`);
  });
  assert.deepStrictEqual(fails, [], `${fails.length}/${C.length} cases failed:\n` + fails.join('\n'));
});

test('x87: the C runtime FDIV check (0x416740) sees a correct FPU', { skip: !have }, () => {
  const ops = require('../runtime/ops');
  const m = rt.createMachine({ exePath: EXE });
  const a = 0x0032F000;   // main thread stack (mapped by initThread)
  rt.dv.setFloat64(a, 4195835, true); rt.dv.setFloat64(a + 8, 3145727, true); rt.dv.setFloat64(a + 16, 1.0, true);
  ops.fld64(m, a); ops.fdiv64(m, a + 8); ops.fmul64(m, a + 8); ops.fsubr64(m, a); ops.fstp64(m, a + 24);
  ops.fld64(m, a + 24); ops.fcomp64(m, a + 16);
  const sw = ops.fnstsw(m);
  assert.strictEqual(m.fpu.top, 0);
  assert.strictEqual(rt.dv.getFloat64(a + 24, true), 0);       // x - (x/y)*y == 0: no FDIV bug
  assert.strictEqual(sw & 0x4500, 0x0100);                     // 0 < 1.0: C0 set
  assert.strictEqual(sw & 0x20, 0x20);                         // the division was inexact: PE
});

function hx(v) { return '0x' + (v >>> 0).toString(16); }
