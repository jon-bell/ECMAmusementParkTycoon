'use strict';
// State hashing: (1) equals a literal BigInt port of rcthook.c hash_range/record_state on random
// state; (2) reproduces the oracle's own TR_CHUNK/TR_FINAL/TR_MSTATE records from an oracle dump
// (test-only use of an oracle output; skipped when the fixture is absent); (3) the mask has the
// documented size and is sensitive where it should be.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { hashState, recordState, isMasked, MASK, STATE_LO, STATE_HI, STATE2_LO, STATE2_HI, CHUNK } = require('../../host/statehash');
const { TraceWriter, readTrace, TR } = require('../../host/trace');

const MEMSZ = 0x9B3000;
function mkmem() { const b = new ArrayBuffer(MEMSZ); return { u8: new Uint8Array(b), u32: new Uint32Array(b) }; }

function refRecordState(u8) {
  const M = (1n << 64n) - 1n, P = 0x100000001b3n;
  const rd = (a) => BigInt(u8[a] | u8[a + 1] << 8 | u8[a + 2] << 16 | u8[a + 3] << 24 >>> 0) & 0xffffffffn;
  let total = 0xcbf29ce484222325n, mtotal = 0xcbf29ce484222325n;
  const chunks = [];
  for (const [lo0, hi0] of [[STATE_LO, STATE_HI], [STATE2_LO, STATE2_HI]]) {
    for (let a = lo0; a < hi0; a += CHUNK) {
      const b = Math.min(a + CHUNK, hi0);
      let h = 0xcbf29ce484222325n, m = mtotal;
      const e = b & ~3;
      for (let p = a; p < e; p += 4) {
        const w = rd(p);
        const bits = BigInt(MASK.bits[p >= STATE2_LO ? Math.ceil((STATE_HI - STATE_LO) / 4) + (p - STATE2_LO) / 4 : (p - STATE_LO) / 4]);
        h = ((h ^ w) * P) & M;
        m = ((m ^ (w & ~bits & 0xffffffffn)) * P) & M;
      }
      for (let q = e; q < b; q++) { h = ((h ^ BigInt(u8[q])) * P) & M; m = ((m ^ BigInt(u8[q])) * P) & M; }
      mtotal = m;
      chunks.push(h);
      total = ((total ^ h) * P) & M;
    }
  }
  return { total, mtotal, chunks };
}
const big = ([lo, hi]) => (BigInt(hi) << 32n) | BigInt(lo);

test('fast hash equals literal BigInt port on random state', () => {
  const { u8, u32 } = mkmem();
  let s = 12345;
  for (let a = STATE_LO; a < STATE2_HI; a++) { s = (Math.imul(s, 1103515245) + 12345) >>> 0; u8[a] = s >>> 24; }
  const h = hashState(u8, u32), r = refRecordState(u8);
  assert.strictEqual(big(h.total), r.total);
  assert.strictEqual(big(h.masked), r.mtotal);
  assert.deepStrictEqual(h.chunks.map(big), r.chunks);
});

test('mask: read from oracle/mask.h; masked bytes change only the raw hash', () => {
  const src = fs.readFileSync(path.join(__dirname, '../../../oracle/mask.h'), 'utf8');
  assert.ok(MASK.dwords.length >= 38373 && /MASK_STRIDE\(0x8DC0B4, 16, 38365\)/.test(src), `${MASK.dwords.length} masked dwords`);
  assert.ok(isMasked(0x5F88A4) && isMasked(0x8DC0B4) && !isMasked(0x8DC0B8));
  const { u8, u32 } = mkmem();
  const h0 = hashState(u8, u32);
  u32[0x5F88A4 >> 2] = 0xd4;              // scenario file handle
  u32[(0x8DC0B4 + 16 * 5) >> 2] = 0x03C80000;
  const h1 = hashState(u8, u32);
  assert.notDeepStrictEqual(h1.total, h0.total);
  assert.deepStrictEqual(h1.masked, h0.masked);
  u8[0x8DC0B4 + 16 * 5 + 4] = 1;          // neighbouring sprite field is not masked
  assert.notDeepStrictEqual(hashState(u8, u32).masked, h0.masked);
  u8[0x9B2300] = 7;                        // trailing byte of DataSeg is hashed
  const h2 = hashState(u8, u32);
  u8[0x9B2300] = 0;
  assert.notDeepStrictEqual(h2.masked, hashState(u8, u32).masked);
});

const FIX = process.env.HOST_DUMP_FIXTURE || path.join(__dirname, '../../../out/host/oracle/dump60');
test('reproduces the oracle trace records from an oracle state dump', { skip: !fs.existsSync(FIX) && 'no oracle fixture' }, () => {
  const dump = fs.readdirSync(FIX).find((f) => f.startsWith('dump_'));
  const d = fs.readFileSync(path.join(FIX, dump));
  const { u8, u32 } = mkmem();
  u8.set(d.subarray(0, STATE_HI - STATE_LO), STATE_LO);
  u8.set(d.subarray(STATE_HI - STATE_LO), STATE2_LO);
  const recs = readTrace(path.join(FIX, 'trace.bin'));
  const fi = recs.findIndex((r) => r[0] === TR.FINAL);
  const want = recs.slice(fi - 61, fi + 2);
  const tw = new TraceWriter(null);
  recordState(tw, TR.FINAL, want[61][1], u8, u32);
  assert.deepStrictEqual(tw.records(), want);
});
