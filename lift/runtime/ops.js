'use strict';
// Helpers called by lifted code: the `rt` object every generated blocks-*.js receives.
//
// Semantics follow the Intel SDM. Where the SDM leaves a flag undefined, the lift reproduces
// what the oracle's CPU (AMD EPYC 7H12, Zen 2) does, as measured by the native single-step
// differential harness (lift/test/cpu). Those choices are collected in HW below and mirrored
// by HW_MODEL in lift/lifter.py (the lifter inlines the static-count cases).

const M = require('./memory');
const { r8, r16, r32, w8, w16, w32, rf64, wf64, mem, pmap } = M;

// Parity: 1 if the low byte has an even number of set bits.
const P = new Uint8Array(256);
for (let i = 0; i < 256; i++) { let b = i, n = 0; while (b) { n += b & 1; b >>= 1; } P[i] = (n & 1) ? 0 : 1; }

let GuestException = null;   // resolved lazily (machine.js requires nothing from here)
function exc(kind, m, eip, detail) {
  if (!GuestException) GuestException = require('./machine').GuestException;
  m.eip = eip >>> 0;
  return new GuestException(kind, eip, detail);
}

// ------------------------------------------------------------------------------------------
// HW: flags the SDM leaves undefined. KEEP = unchanged. (Calibrated: see lift/test/cpu.)
// ------------------------------------------------------------------------------------------
// Measured on the oracle machine (AMD EPYC 7H12, Zen 2) by lift/test/cpu/flagfit.py:
//   AND/OR/XOR/TEST: AF = 0.   SHL/SHR/SAR/SHRD (count != 0): AF = 1.
//   OF of shifts/rotates at every nonzero count: the count-1 formula generalised
//     (SHL, ROL, RCL: msb(r)^CF; SHR, SHRD, ROR, RCR: msb(r)^msb-1(r); SAR: 0).
//   8/16-bit SHL/SHR by more than the width: CF = 0.
//   MUL/IMUL: SF ZF AF PF unchanged.  BT*: all but CF unchanged.  BSF: only ZF changes
//     (zero source: destination unchanged).
//   DIV/IDIV: PF = 0, AF = 1, ZF = 0, SF = 0, CF and OF unchanged.
const HW = {
  logicAF: 0,
  shiftAF: 1,
};

function szp(m, r, w) { m.zf = r === 0 ? 1 : 0; m.sf = r >>> (w - 1); m.pf = P[r & 0xFF]; }

// ---------------- multiply ----------------
// 32x32 -> 64 bit products; results in S[0] (low) and S[1] (high).
const S = new Uint32Array(2);
function mulu(a, b) {
  const al = a & 0xFFFF, ah = a >>> 16, bl = b & 0xFFFF, bh = b >>> 16;
  const ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  const mid = (ll >>> 16) + (lh & 0xFFFF) + (hl & 0xFFFF);
  S[0] = ((mid & 0xFFFF) * 0x10000 + (ll & 0xFFFF));
  S[1] = hh + (lh >>> 16) + (hl >>> 16) + Math.floor(mid / 0x10000);
}
function mulFlagsHW(m, lo, w) { /* SF ZF AF PF after MUL/IMUL: unchanged on the oracle CPU */ }

function mul8(m, s) {
  const p = (m.eax & 0xFF) * s;
  m.eax = (m.eax & 0xFFFF0000 | p) >>> 0;
  m.cf = m.of = p > 0xFF ? 1 : 0;
  mulFlagsHW(m, p & 0xFF, 8);
}
function mul16(m, s) {
  const p = (m.eax & 0xFFFF) * s;
  m.eax = (m.eax & 0xFFFF0000 | (p & 0xFFFF)) >>> 0;
  m.edx = (m.edx & 0xFFFF0000 | (p >>> 16)) >>> 0;
  m.cf = m.of = p > 0xFFFF ? 1 : 0;
  mulFlagsHW(m, p & 0xFFFF, 16);
}
function mul32(m, s) {
  mulu(m.eax, s);
  m.eax = S[0]; m.edx = S[1];
  m.cf = m.of = S[1] !== 0 ? 1 : 0;
  mulFlagsHW(m, S[0], 32);
}
function imul8(m, s) {
  const p = (m.eax << 24 >> 24) * (s << 24 >> 24);
  m.eax = (m.eax & 0xFFFF0000 | (p & 0xFFFF)) >>> 0;
  m.cf = m.of = p !== (p << 24 >> 24) ? 1 : 0;
  mulFlagsHW(m, p & 0xFF, 8);
}
function imul16(m, s) {
  const p = (m.eax << 16 >> 16) * (s << 16 >> 16);
  m.eax = (m.eax & 0xFFFF0000 | (p & 0xFFFF)) >>> 0;
  m.edx = (m.edx & 0xFFFF0000 | ((p >> 16) & 0xFFFF)) >>> 0;
  m.cf = m.of = p !== (p << 16 >> 16) ? 1 : 0;
  mulFlagsHW(m, p & 0xFFFF, 16);
}
function imul32(m, s) {
  const a = m.eax;
  mulu(a, s);
  const lo = S[0];
  // signed high half = unsigned high - (a < 0 ? s : 0) - (s < 0 ? a : 0)  (mod 2^32)
  let hi = S[1];
  if (a & 0x80000000) hi -= s;
  if (s & 0x80000000) hi -= a;
  hi = hi >>> 0;
  m.eax = lo; m.edx = hi;
  m.cf = m.of = hi !== ((lo >> 31) >>> 0) ? 1 : 0;
  mulFlagsHW(m, lo, 32);
}

// ---------------- divide ----------------
// #DE (divide by zero or quotient overflow) -> GuestException('DE') with m.eip = the instruction
// and every register unchanged. Wine reports both cases as EXCEPTION_INT_DIVIDE_BY_ZERO
// (Linux delivers SIGFPE/FPE_INTDIV for #DE).
function divFlagsHW(m) { m.pf = 0; m.af = 1; m.zf = 0; m.sf = 0; }

function div8(m, s, eip) {
  const n = m.eax & 0xFFFF;
  if (s === 0) throw exc('DE', m, eip, 'divide by zero');
  const q = Math.floor(n / s);
  if (q > 0xFF) throw exc('DE', m, eip, 'quotient overflow');
  m.eax = (m.eax & 0xFFFF0000 | (n % s) << 8 | q) >>> 0;
  divFlagsHW(m);
}
function div16(m, s, eip) {
  const n = ((m.edx & 0xFFFF) * 0x10000 + (m.eax & 0xFFFF));
  if (s === 0) throw exc('DE', m, eip, 'divide by zero');
  const r = n % s, q = (n - r) / s;
  if (q > 0xFFFF) throw exc('DE', m, eip, 'quotient overflow');
  m.eax = (m.eax & 0xFFFF0000 | q) >>> 0;
  m.edx = (m.edx & 0xFFFF0000 | r) >>> 0;
  divFlagsHW(m);
}
// unsigned (hi:lo) / s with hi < s; quotient in S[0], remainder in S[1]. Exact (all < 2^53).
function udiv64(hi, lo, s) {
  const t1 = hi * 0x10000 + (lo >>> 16);
  const r1 = t1 % s, q1 = (t1 - r1) / s;
  const t2 = r1 * 0x10000 + (lo & 0xFFFF);
  const r2 = t2 % s, q2 = (t2 - r2) / s;
  S[0] = q1 * 0x10000 + q2; S[1] = r2;
}
function div32(m, s, eip) {
  if (s === 0) throw exc('DE', m, eip, 'divide by zero');
  const hi = m.edx, lo = m.eax;
  if (hi >= s) throw exc('DE', m, eip, 'quotient overflow');
  udiv64(hi, lo, s);
  m.eax = S[0]; m.edx = S[1];
  divFlagsHW(m);
}
function idiv8(m, s, eip) {
  const n = m.eax << 16 >> 16;                 // signed 16-bit dividend (ax)
  const d = s << 24 >> 24;
  if (d === 0) throw exc('DE', m, eip, 'divide by zero');
  const q = Math.trunc(n / d), r = n - q * d;
  if (q > 0x7F || q < -0x80) throw exc('DE', m, eip, 'quotient overflow');
  m.eax = (m.eax & 0xFFFF0000 | (r & 0xFF) << 8 | (q & 0xFF)) >>> 0;
  divFlagsHW(m);
}
function idiv16(m, s, eip) {
  const n = ((m.edx & 0xFFFF) << 16 | (m.eax & 0xFFFF)) | 0;   // signed 32-bit dividend
  const d = s << 16 >> 16;
  if (d === 0) throw exc('DE', m, eip, 'divide by zero');
  const q = Math.trunc(n / d);       // |n| < 2^31: n / d correctly rounded, trunc exact (see README)
  const r = n - q * d;
  if (q > 0x7FFF || q < -0x8000) throw exc('DE', m, eip, 'quotient overflow');
  m.eax = (m.eax & 0xFFFF0000 | (q & 0xFFFF)) >>> 0;
  m.edx = (m.edx & 0xFFFF0000 | (r & 0xFFFF)) >>> 0;
  divFlagsHW(m);
}
function idiv32(m, s, eip) {
  const d = s | 0;
  if (d === 0) throw exc('DE', m, eip, 'divide by zero');
  let hi = m.edx, lo = m.eax;
  const nneg = (hi & 0x80000000) !== 0;
  if (nneg) { lo = (~lo + 1) >>> 0; hi = (~hi + (lo === 0 ? 1 : 0)) >>> 0; }   // |dividend|
  const ad = d < 0 ? -d : d;                                                    // |divisor| <= 2^31
  if (hi >= ad) throw exc('DE', m, eip, 'quotient overflow');
  udiv64(hi, lo, ad);
  let q = S[0], r = S[1];
  const qneg = nneg !== (d < 0);
  if (qneg ? q > 0x80000000 : q > 0x7FFFFFFF) throw exc('DE', m, eip, 'quotient overflow');
  q = qneg ? (-q) >>> 0 : q;
  r = nneg ? (-r) >>> 0 : r;
  m.eax = q; m.edx = r;
  divFlagsHW(m);
}

// ---------------- shifts and rotates with a count in CL ----------------
// c: the CL value (0..255); masked to 5 bits. Count 0: nothing changes (flags included).
// OF is defined by the SDM only for count 1; for other counts the HW model applies.
function shlOF(m, r, w, c, cf) { m.of = (r >>> (w - 1)) ^ cf; }
function mk(w) {
  const M_ = w === 32 ? 0xFFFFFFFF : (1 << w) - 1;
  const norm = w === 32 ? (v) => v >>> 0 : (v) => v & M_;
  const sx = w === 32 ? (v) => v | 0 : (v) => v << (32 - w) >> (32 - w);
  return {
    shl(m, d, c) {
      c &= 31; if (c === 0) return d;
      const r = norm(d << c);
      const cf = c <= w ? (d >>> (w - c)) & 1 : 0;
      m.cf = cf; shlOF(m, r, w, c, cf); m.af = HW.shiftAF; szp(m, r, w);
      return r;
    },
    shr(m, d, c) {
      c &= 31; if (c === 0) return d;
      const r = d >>> c;
      m.cf = c <= w ? (d >>> (c - 1)) & 1 : 0;
      m.of = (r >>> (w - 1)) ^ ((r >>> (w - 2)) & 1);
      m.af = HW.shiftAF; szp(m, r, w);
      return r;
    },
    sar(m, d, c) {
      c &= 31; if (c === 0) return d;
      const ds = sx(d), r = norm(ds >> c);
      m.cf = (ds >> (c - 1)) & 1;
      m.of = 0;
      m.af = HW.shiftAF; szp(m, r, w);
      return r;
    },
    rol(m, d, c) {
      c &= 31; if (c === 0) return d;
      const k = c % w;
      const r = k === 0 ? d : norm(d << k | d >>> (w - k));
      m.cf = r & 1;
      m.of = (r >>> (w - 1)) ^ (r & 1);
      return r;
    },
    ror(m, d, c) {
      c &= 31; if (c === 0) return d;
      const k = c % w;
      const r = k === 0 ? d : norm(d >>> k | d << (w - k));
      m.cf = r >>> (w - 1);
      m.of = (r >>> (w - 1)) ^ ((r >>> (w - 2)) & 1);
      return r;
    },
    rcl(m, d, c) {
      c &= 31; if (c === 0) return d;
      const k = w < 32 ? c % (w + 1) : c;
      if (k === 0) { m.of = (d >>> (w - 1)) ^ m.cf; return d; }
      const ci = m.cf;
      let r, co;
      if (w < 32) {
        const x = ci << w | d, y = (x << k | x >>> (w + 1 - k)) & ((1 << (w + 1)) - 1);
        r = y & M_; co = y >>> w;
      } else if (k === 1) { r = (d << 1 | ci) >>> 0; co = d >>> 31; }
      else { r = (d << k | ci << (k - 1) | d >>> (33 - k)) >>> 0; co = (d >>> (32 - k)) & 1; }
      m.cf = co;
      m.of = (r >>> (w - 1)) ^ co;
      return r;
    },
    rcr(m, d, c) {
      c &= 31; if (c === 0) return d;
      const k = w < 32 ? c % (w + 1) : c;
      if (k === 0) { m.of = (d >>> (w - 1)) ^ ((d >>> (w - 2)) & 1); return d; }
      const ci = m.cf;
      let r, co;
      if (w < 32) {
        const x = ci << w | d, y = (x >>> k | x << (w + 1 - k)) & ((1 << (w + 1)) - 1);
        r = y & M_; co = y >>> w;
      } else if (k === 1) { r = (d >>> 1 | ci << 31) >>> 0; co = d & 1; }
      else { r = (d >>> k | ci << (32 - k) | d << (33 - k)) >>> 0; co = (d >>> (k - 1)) & 1; }
      m.of = (r >>> (w - 1)) ^ ((r >>> (w - 2)) & 1);
      m.cf = co;
      return r;
    },
  };
}
const S8 = mk(8), S16 = mk(16), S32 = mk(32);
function shrd32(m, d, s, c) {
  c &= 31; if (c === 0) return d;
  const r = (d >>> c | s << (32 - c)) >>> 0;
  m.cf = (d >>> (c - 1)) & 1;
  m.of = (r >>> 31) ^ ((r >>> 30) & 1);
  m.af = HW.shiftAF; szp(m, r, 32);
  return r;
}

// ---------------- string instructions ----------------
// Element by element, exactly as the CPU does (overlapping moves replicate patterns; DF=1 runs
// backwards). esi/edi/ecx are updated as they go, so a fault leaves the registers at the
// faulting element as on hardware.
function movsN(m, n, rd, wr, count) {
  const step = m.df ? -n : n;
  let si = m.esi, di = m.edi;
  for (let k = 0; k < count; k++) {
    wr(di, rd(si));
    si = (si + step) >>> 0; di = (di + step) >>> 0;
    m.esi = si; m.edi = di;
  }
}
function movs8(m) { movsN(m, 1, r8, w8, 1); }
function movs16(m) { movsN(m, 2, r16, w16, 1); }
function movs32(m) { movsN(m, 4, r32, w32, 1); }
function repMovs(m, n, rd, wr) {
  let c = m.ecx;
  if (c === 0) return;
  const si = m.esi, di = m.edi, bytes = c * n;
  // Fast path: forward, no overlap hazard, ranges mapped (whole-range checks fault like the
  // element loop would only if the first element faults; otherwise fall back to the loop).
  if (!m.df && !M.writeLogging() && bytes <= 0x4000000 && si + bytes <= M.MEM_SIZE && di + bytes <= M.MEM_SIZE &&
      (di <= si || di >= si + bytes) && rangeOk(si, bytes, 1) && rangeOk(di, bytes, 2)) {
    mem.copyWithin(di, si, si + bytes);
    m.esi = (si + bytes) >>> 0; m.edi = (di + bytes) >>> 0; m.ecx = 0;
    return;
  }
  const step = m.df ? -n : n;
  let s = si, d = di;
  while (c !== 0) {
    wr(d, rd(s));
    s = (s + step) >>> 0; d = (d + step) >>> 0; c = (c - 1) >>> 0;
    m.esi = s; m.edi = d; m.ecx = c;
  }
}
function rangeOk(a, n, prot) {
  for (let p = a >>> 12, e = (a + n - 1) >>> 12; p <= e; p++) if ((pmap[p] & prot) === 0) return false;
  return true;
}
function movs8Rep(m) { repMovs(m, 1, r8, w8); }
function movs16Rep(m) { repMovs(m, 2, r16, w16); }
function movs32Rep(m) { repMovs(m, 4, r32, w32); }

function stos8(m) { w8(m.edi, m.eax & 0xFF); m.edi = (m.edi + (m.df ? -1 : 1)) >>> 0; }
function stos16(m) { w16(m.edi, m.eax & 0xFFFF); m.edi = (m.edi + (m.df ? -2 : 2)) >>> 0; }
function stos32(m) { w32(m.edi, m.eax); m.edi = (m.edi + (m.df ? -4 : 4)) >>> 0; }
function repStos(m, n, wr, v) {
  let c = m.ecx;
  if (c === 0) return;
  const di = m.edi, bytes = c * n;
  if (!m.df && n === 1 && !M.writeLogging() && bytes <= 0x4000000 && di + bytes <= M.MEM_SIZE && rangeOk(di, bytes, 2)) {
    mem.fill(v, di, di + bytes);
    m.edi = (di + bytes) >>> 0; m.ecx = 0;
    return;
  }
  const step = m.df ? -n : n;
  let d = di;
  while (c !== 0) {
    wr(d, v);
    d = (d + step) >>> 0; c = (c - 1) >>> 0;
    m.edi = d; m.ecx = c;
  }
}
function stos8Rep(m) { repStos(m, 1, w8, m.eax & 0xFF); }
function stos16Rep(m) { repStos(m, 2, w16, m.eax & 0xFFFF); }
function stos32Rep(m) { repStos(m, 4, w32, m.eax); }

// scasb: flags of cmp al, [edi]
function cmp8Flags(m, d, s) {
  const r = (d - s) & 0xFF;
  m.cf = d < s ? 1 : 0; m.of = ((d ^ s) & (d ^ r)) >>> 7 & 1; m.af = (d ^ s ^ r) >>> 4 & 1;
  m.zf = r === 0 ? 1 : 0; m.sf = r >>> 7; m.pf = P[r];
}
function scas8(m) {
  cmp8Flags(m, m.eax & 0xFF, r8(m.edi));
  m.edi = (m.edi + (m.df ? -1 : 1)) >>> 0;
}
function scas8Repne(m) {
  const al = m.eax & 0xFF, step = m.df ? -1 : 1;
  let c = m.ecx, d = m.edi;
  while (c !== 0) {
    const v = r8(d);
    d = (d + step) >>> 0; c = (c - 1) >>> 0;
    m.edi = d; m.ecx = c;
    cmp8Flags(m, al, v);
    if (m.zf) break;
  }
}

// ---------------- x87 (C runtime only: 15 instructions in .text) ----------------
// Model: the register stack holds JS doubles. Exact for what rct.exe executes: every
// operation is a double-precision load/op/store with the control word's precision control at
// 53 bits (0x027F, the Win32 default) and round-to-nearest, where x87 rounding equals IEEE
// double rounding. fldcw records the control word; other precision/rounding settings are not
// modelled (an arithmetic op under them throws, rather than silently differ).
// Status word: C0/C2/C3 from fcomp, TOP, and the precision-exception flag PE (bit 5), set when
// a result is inexact (detected exactly with error-free transformations).
function fpuCheck(m) {
  if ((m.fpu.cw & 0x0F00) !== 0x0200) throw new Error(`x87 control word ${m.fpu.cw.toString(16)}: only 53-bit precision, round-to-nearest is modelled`);
}
function fpush(m, v) { const f = m.fpu; f.top = (f.top - 1) & 7; f.st[f.top] = v; f.tag &= ~(1 << f.top); }
function fpop(m) { const f = m.fpu; f.tag |= 1 << f.top; f.top = (f.top + 1) & 7; }
const SPLIT = 134217729; // 2^27 + 1 (Dekker)
function twoProdErr(a, b, p) {
  const ca = SPLIT * a, ah = ca - (ca - a), al = a - ah;
  const cb = SPLIT * b, bh = cb - (cb - b), bl = b - bh;
  return ((ah * bh - p) + ah * bl + al * bh) + al * bl;
}
function inexact(m) { m.fpu.sw |= 0x20; }
function fld64(m, a) { fpush(m, rf64(a)); }
function fstp64(m, a) { wf64(a, m.fpu.st[m.fpu.top]); fpop(m); }
function fmul64(m, a) {
  fpuCheck(m); const f = m.fpu, x = f.st[f.top], y = rf64(a), p = x * y;
  if (isFinite(p) && twoProdErr(x, y, p) !== 0) inexact(m);
  f.st[f.top] = p;
}
function fdiv64(m, a) {
  fpuCheck(m); const f = m.fpu, x = f.st[f.top], y = rf64(a), q = x / y;
  if (isFinite(q) && y !== 0 && (q * y !== x || twoProdErr(q, y, q * y) !== 0)) inexact(m);
  f.st[f.top] = q;
}
function fsubr64(m, a) {
  fpuCheck(m); const f = m.fpu, x = rf64(a), y = f.st[f.top], d = x - y;
  // two-sum error term
  const bv = d - x, e = (x - (d - bv)) + (-y - bv);
  if (isFinite(d) && e !== 0) inexact(m);
  f.st[f.top] = d;
}
function fcomp64(m, a) {
  const f = m.fpu, x = f.st[f.top], y = rf64(a);
  let c = 0;                                    // C3 C2 C0 = 0 0 0: st0 > src
  if (x < y) c = 0x0100;                        // C0
  else if (x === y) c = 0x4000;                 // C3
  else if (!(x > y)) c = 0x4500;                // unordered
  f.sw = (f.sw & ~0x4700) | c;                  // C1 cleared
  fpop(m);
}
function fnstsw(m) { const f = m.fpu; return ((f.sw & ~0x3800) | (f.top << 11)) & 0xFFFF; }
function fldcw(m, v) { m.fpu.cw = v & 0xFFFF; }

// ---------------- misc ----------------
// CPUID: the C runtime calls it once (0x402E76, leaf 1) to test the MMX bit (edx bit 23)
// unless GetSystemInfo reports a 386/486 (under the oracle it reports 586, so it is reached).
// ENVIRONMENT-DEPENDENT: these are the values of the oracle's machine (AMD EPYC 7H12, family
// 0x17, under a hypervisor: ecx bit 31), read natively with cpuid (Wine does not intercept it).
// Leaf-1 ebx bits 31..24 are the initial APIC id of whichever core ran the instruction (varies
// run to run); fixed at 0 here. rct.exe keeps only edx (0x178BFBFF: MMX set); ebx is restored by
// the caller; eax/ecx are left as the CPU set them.
const CPUID = {
  0: [0x00000010, 0x68747541, 0x444D4163, 0x69746E65],   // max leaf 0x10, "AuthenticAMD"
  1: [0x00830F10, 0x00640800, 0xFFF83203, 0x178BFBFF],
};
function cpuid(m) {
  const v = CPUID[m.eax] || [0, 0, 0, 0];
  m.eax = v[0] >>> 0; m.ebx = v[1] >>> 0; m.ecx = v[2] >>> 0; m.edx = v[3] >>> 0;
}
function int3(m, eip) { throw exc('BP', m, eip, 'int3'); }

module.exports = {
  ...M, P, S, HW, CPUID,
  mul8, mul16, mul32, imul8, imul16, imul32, div8, div16, div32, idiv8, idiv16, idiv32, mulu, udiv64,
  shl8: S8.shl, shl16: S16.shl, shl32: S32.shl, shr8: S8.shr, shr16: S16.shr, shr32: S32.shr,
  sar8: S8.sar, sar16: S16.sar, sar32: S32.sar, rol8: S8.rol, rol16: S16.rol, rol32: S32.rol,
  ror8: S8.ror, ror16: S16.ror, ror32: S32.ror, rcl8: S8.rcl, rcl16: S16.rcl, rcl32: S32.rcl,
  rcr8: S8.rcr, rcr16: S16.rcr, rcr32: S32.rcr, shrd32,
  movs8, movs16, movs32, movs8Rep, movs16Rep, movs32Rep, stos8, stos16, stos32, stos8Rep, stos16Rep, stos32Rep,
  scas8, scas8Repne,
  fld64, fstp64, fmul64, fdiv64, fsubr64, fcomp64, fnstsw, fldcw, cpuid, int3,
};
