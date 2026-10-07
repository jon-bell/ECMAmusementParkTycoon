'use strict';
// Guest memory: one little-endian byte array covering [0, MEM_SIZE), with a 4 KiB page map.
//
// Every guest access made by lifted code goes through r8/r16/r32/w8/w16/w32. An access to a
// page that is not mapped with the needed permission throws GuestFault. Page map bits:
//   1 = readable, 2 = writable, 4 = code (lifted ahead of time: a write would be self-modifying)
// Pages outside [0, MEM_SIZE) are never mapped, so the page map also does the bounds check.
// The first 64 KiB are never mapped (as on Windows: null-pointer accesses fault).
//
// The host may read and write `mem`/`dv` directly (no checks) for its own bookkeeping.

const C = require('./constants');

const MEM_SIZE = C.MEM_SIZE;
const mem = new Uint8Array(MEM_SIZE);
const dv = new DataView(mem.buffer);
const pmap = new Uint8Array(1 << 20);   // one entry per 4 KiB page of the 32-bit space

const PROT_R = 1, PROT_W = 2, PROT_CODE = 4, PROT_RW = 3;

const hex = (v) => '0x' + (v >>> 0).toString(16).toUpperCase().padStart(8, '0');

class GuestFault extends Error {
  // op: 'read' | 'write'; addr: guest address; size: bytes
  constructor(op, addr, size, why) {
    super(`GuestFault: ${op} of ${size} byte(s) at ${hex(addr)}${why ? ' (' + why + ')' : ''}`);
    this.name = 'GuestFault';
    this.op = op; this.addr = addr >>> 0; this.size = size; this.why = why || '';
    this.blockEip = undefined;   // filled in by the dispatcher: start of the block that faulted
  }
}

function why(a, n, op) {
  a >>>= 0;
  if (a >= MEM_SIZE || a + n > MEM_SIZE) return 'outside guest memory';
  if (a < 0x10000) return 'null page';
  for (let k = 0; k < n; k++) {
    const p = pmap[(a + k) >>> 12];
    if (!(p & PROT_R)) return 'unmapped page';
    if (op === 'write' && !(p & PROT_W)) {
      return (p & PROT_CODE) ? 'write into a lifted code section (self-modifying code is not supported)' : 'write to a read-only page';
    }
  }
  return '';
}
function rfault(a, n) { throw new GuestFault('read', a, n, why(a, n, 'read')); }
function wfault(a, n) { throw new GuestFault('write', a, n, why(a, n, 'write')); }

// Write log (register capture, lift/runtime/capture.js): fn(size, addr, value) after every guest
// store, or null. One predictable branch per store when off.
let wlog = null;
function setWriteLog(fn) { wlog = fn; }
function writeLogging() { return wlog !== null; }

// --- accessors used by lifted code (addresses are uint32 numbers) ---
function r8(a) {
  if ((pmap[a >>> 12] & 1) === 0) rfault(a, 1);
  return mem[a];
}
function r16(a) {
  if ((pmap[a >>> 12] & pmap[(a + 1) >>> 12] & 1) === 0) rfault(a, 2);
  return dv.getUint16(a, true);
}
function r32(a) {
  if ((pmap[a >>> 12] & pmap[(a + 3) >>> 12] & 1) === 0) rfault(a, 4);
  return dv.getUint32(a, true);
}
function w8(a, v) {
  if ((pmap[a >>> 12] & 2) === 0) wfault(a, 1);
  mem[a] = v;
  if (wlog !== null) wlog(1, a, mem[a]);
}
function w16(a, v) {
  if ((pmap[a >>> 12] & pmap[(a + 1) >>> 12] & 2) === 0) wfault(a, 2);
  dv.setUint16(a, v, true);
  if (wlog !== null) wlog(2, a, dv.getUint16(a, true));
}
function w32(a, v) {
  if ((pmap[a >>> 12] & pmap[(a + 3) >>> 12] & 2) === 0) wfault(a, 4);
  dv.setUint32(a, v, true);
  if (wlog !== null) wlog(4, a, dv.getUint32(a, true));
}
function rf64(a) {
  if ((pmap[a >>> 12] & pmap[(a + 7) >>> 12] & 1) === 0) rfault(a, 8);
  return dv.getFloat64(a, true);
}
function wf64(a, v) {
  if ((pmap[a >>> 12] & pmap[(a + 7) >>> 12] & 2) === 0) wfault(a, 8);
  dv.setFloat64(a, v, true);
  if (wlog !== null) { wlog(4, a, dv.getUint32(a, true)); wlog(4, (a + 4) >>> 0, dv.getUint32(a + 4, true)); }
}

// Checked range access (string instructions use these for whole-range fast paths).
function checkRange(a, n, prot) {
  if (n === 0) return;
  const end = a + n - 1;
  if (end >= MEM_SIZE || a >= MEM_SIZE) (prot & 2 ? wfault : rfault)(a, n);
  for (let p = a >>> 12; p <= end >>> 12; p++) {
    if ((pmap[p] & prot) !== prot) (prot & 2 ? wfault : rfault)(p << 12 > a ? p << 12 : a, 1);
  }
}

// --- page map management (host side) ---
function mapPages(addr, size, prot) {
  addr >>>= 0;
  if (size <= 0) return;
  if (addr + size > MEM_SIZE) throw new RangeError(`mapPages ${hex(addr)}+${size.toString(16)} beyond MEM_SIZE`);
  const lo = addr >>> 12, hi = (addr + size - 1) >>> 12;
  for (let p = lo; p <= hi; p++) pmap[p] = prot;
}
function unmapPages(addr, size) { mapPages(addr, size, 0); }
function protOf(addr) { return pmap[(addr >>> 0) >>> 12]; }
function resetMemory() { mem.fill(0); pmap.fill(0); }

// --- host conveniences (unchecked: the host is trusted, but stay inside MEM_SIZE) ---
function readBytes(a, n) { return mem.slice(a, a + n); }
function writeBytes(a, bytes) { mem.set(bytes, a); }
function readCString(a, max = 0x10000) {
  let s = '';
  for (let k = 0; k < max; k++) { const c = mem[a + k]; if (c === 0) break; s += String.fromCharCode(c); }
  return s;
}
function writeCString(a, s) {
  for (let k = 0; k < s.length; k++) mem[a + k] = s.charCodeAt(k) & 0xFF;
  mem[a + s.length] = 0;
}
function readWString(a, max = 0x10000) {
  let s = '';
  for (let k = 0; k < max; k++) { const c = dv.getUint16(a + 2 * k, true); if (c === 0) break; s += String.fromCharCode(c); }
  return s;
}

module.exports = {
  MEM_SIZE, mem, dv, pmap, PROT_R, PROT_W, PROT_CODE, PROT_RW, GuestFault, hex,
  r8, r16, r32, w8, w16, w32, rf64, wf64, checkRange, rfault, wfault,
  mapPages, unmapPages, protOf, resetMemory, setWriteLog, writeLogging,
  readBytes, writeBytes, readCString, writeCString, readWString,
};
