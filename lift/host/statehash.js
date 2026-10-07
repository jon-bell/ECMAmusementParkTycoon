'use strict';
// State hashing exactly as record_state()/hash_range() in oracle/rcthook.c:
//   FNV-1a 64 over 32-bit words of DATASEG [0x5F4000, 0x9A161C) and DataSeg [0x9A2000, 0x9B2301),
//   one hash per 64 KiB chunk (TR_CHUNK), the total = FNV fold of the chunk hashes (TR_STATE or
//   TR_FINAL), and one continuous masked hash over the same words with the OS-derived dwords read
//   as 0 (TR_MSTATE). A trailing partial word is hashed byte by byte in both.
// 64-bit arithmetic is done on two uint32 halves (BigInt would be ~50x slower per tick).
const { TR } = require('./trace');

const STATE_LO = 0x5F4000, STATE_HI = 0x9A161C, STATE2_LO = 0x9A2000, STATE2_HI = 0x9B2301;
const CHUNK = 0x10000;
const RANGES = [[STATE_LO, STATE_HI], [STATE2_LO, STATE2_HI]];
const BASIS_LO = 0x84222325, BASIS_HI = 0xcbf29ce4;   // 0xcbf29ce484222325
const PRIME_LO = 0x1b3;                                // prime 0x100000001b3 = 2^40 + 0x1b3

// The mask: state bytes that hold OS-chosen values, read as 0 in the masked hash (TR_MSTATE).
// Single source of truth: oracle/mask.h (MASK_DWORD(addr): the 4 bytes at addr, any alignment;
// MASK_STRIDE(base, stride, count)), parsed here as rcthook.c's mask_build() includes it. A masked
// byte contributes 0 to its 32-bit word; the trailing partial word of DataSeg is never masked.
const fs = require('fs');
const path = require('path');
const MASK_H = path.join(__dirname, '../../oracle/mask.h');
const num = (t) => Number(t.trim().replace(/u$/i, ''));
function loadMask() {
  const t = fs.readFileSync(MASK_H, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const dwords = [];
  for (const m of t.matchAll(/MASK_(DWORD|STRIDE)\s*\(([^)]*)\)/g)) {
    const a = m[2].split(',').map(num);
    if (m[1] === 'DWORD') { if (a.length !== 1) throw new Error(`oracle/mask.h: bad ${m[0]}`); dwords.push(a[0]); }
    else { if (a.length !== 3) throw new Error(`oracle/mask.h: bad ${m[0]}`); for (let i = 0; i < a[2]; i++) dwords.push(a[0] + i * a[1]); }
  }
  if (!dwords.length) throw new Error('oracle/mask.h: no entries');
  return dwords;
}
const NW1 = Math.ceil((STATE_HI - STATE_LO) / 4), NW2 = Math.ceil((STATE2_HI - STATE2_LO) / 4);
const MASK_DWORDS = loadMask();
const MASKBITS = new Uint32Array(NW1 + NW2);   // per hashed word: the masked bits
for (const d of MASK_DWORDS) {
  for (let b = d; b < d + 4; b++) {
    let i, base;
    if (b >= STATE_LO && b < STATE_HI) { i = (b - STATE_LO) >>> 2; base = STATE_LO; }
    else if (b >= STATE2_LO && b < STATE2_HI) { i = NW1 + ((b - STATE2_LO) >>> 2); base = STATE2_LO; }
    else continue;
    MASKBITS[i] = (MASKBITS[i] | (0xFF << (8 * ((b - base) & 3)))) >>> 0;
  }
}
/** Does the mask cover any byte of the word at a (a word-aligned state address)? */
function isMasked(a) {
  const i = a >= STATE2_LO ? NW1 + ((a - STATE2_LO) >>> 2) : (a - STATE_LO) >>> 2;
  return MASKBITS[i] !== 0;
}
const MASK = { dwords: MASK_DWORDS, bits: MASKBITS, source: 'oracle/mask.h' };

// Chunks of the hashed ranges, with the offset of their first word in MASKBITS
const CHUNKS = [];
for (const [lo0, hi0] of RANGES) {
  for (let a = lo0; a < hi0; a += CHUNK) {
    const b = Math.min(a + CHUNK, hi0);
    CHUNKS.push({ lo: a, hi: b, end: b & ~3, mk: lo0 === STATE2_LO ? NW1 + ((a - STATE2_LO) >>> 2) : (a - STATE_LO) >>> 2 });
  }
}

/**
 * Hash the state. `u8`/`u32` are views of guest memory starting at guest address 0.
 * Returns {chunks: [[lo,hi]...], total: [lo,hi], masked: [lo,hi]}.
 */
function hashState(u8, u32) {
  let tlo = BASIS_LO, thi = BASIS_HI;     // total over chunk hashes
  let mlo = BASIS_LO, mhi = BASIS_HI;     // continuous masked hash
  const chunks = new Array(CHUNKS.length);
  for (let ci = 0; ci < CHUNKS.length; ci++) {
    const c = CHUNKS[ci];
    let hlo = BASIS_LO, hhi = BASIS_HI;
    const w0 = c.lo >>> 2;
    const we = c.end >>> 2;
    let mi = c.mk;
    for (let wi = w0; wi < we; wi++, mi++) {
      const w = u32[wi];
      // raw: h = (h ^ w) * P
      let x = (hlo ^ w) >>> 0;
      let t = x * PRIME_LO;
      hhi = (Math.imul(hhi, PRIME_LO) + Math.floor(t / 4294967296) + (x << 8)) >>> 0;
      hlo = t >>> 0;
      // masked: masked bytes read as 0
      x = (mlo ^ (w & ~MASKBITS[mi])) >>> 0;
      t = x * PRIME_LO;
      mhi = (Math.imul(mhi, PRIME_LO) + Math.floor(t / 4294967296) + (x << 8)) >>> 0;
      mlo = t >>> 0;
    }
    for (let a = c.end; a < c.hi; a++) {
      const v = u8[a];
      let x = (hlo ^ v) >>> 0, t = x * PRIME_LO;
      hhi = (Math.imul(hhi, PRIME_LO) + Math.floor(t / 4294967296) + (x << 8)) >>> 0;
      hlo = t >>> 0;
      x = (mlo ^ v) >>> 0; t = x * PRIME_LO;
      mhi = (Math.imul(mhi, PRIME_LO) + Math.floor(t / 4294967296) + (x << 8)) >>> 0;
      mlo = t >>> 0;
    }
    chunks[ci] = [hlo, hhi];
    // total = (total ^ h) * P  (64-bit xor)
    const xl = (tlo ^ hlo) >>> 0, xh = (thi ^ hhi) >>> 0;
    const t = xl * PRIME_LO;
    thi = (Math.imul(xh, PRIME_LO) + Math.floor(t / 4294967296) + (xl << 8)) >>> 0;
    tlo = t >>> 0;
  }
  return { chunks, total: [tlo, thi], masked: [mlo, mhi] };
}

/** record_state(kind): TR_CHUNK per chunk (if enabled), then kind (TR_STATE/TR_FINAL), TR_MSTATE. */
function recordState(trace, kind, tick, u8, u32, withChunks = true) {
  const h = hashState(u8, u32);
  if (withChunks) for (let i = 0; i < h.chunks.length; i++) trace.rec(TR.CHUNK, i, h.chunks[i][0], h.chunks[i][1]);
  trace.rec(kind, tick, h.total[0], h.total[1]);
  trace.rec(TR.MSTATE, tick, h.masked[0], h.masked[1]);
  return h;
}

module.exports = { hashState, recordState, isMasked, MASK, STATE_LO, STATE_HI, STATE2_LO, STATE2_HI, CHUNK, CHUNKS };
