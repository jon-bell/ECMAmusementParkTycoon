'use strict';
// Host-side access to guest memory. The host is trusted: these accessors bypass the guest page
// map (lift/runtime/memory.js `mem`/`dv`), but stay inside guest memory. Strings are ANSI
// (code page 1252 -> latin1 for the bytes the game uses) or UTF-16LE.
const M = require('../runtime/memory');

const r8 = (a) => M.mem[a >>> 0];
const r16 = (a) => M.dv.getUint16(a >>> 0, true);
const r32 = (a) => M.dv.getUint32(a >>> 0, true);
const s32 = (a) => M.dv.getInt32(a >>> 0, true);
const w8 = (a, v) => { M.mem[a >>> 0] = v; };
const w16 = (a, v) => M.dv.setUint16(a >>> 0, v & 0xFFFF, true);
const w32 = (a, v) => M.dv.setUint32(a >>> 0, v >>> 0, true);

function rstr(a, max = 0x10000) {
  a >>>= 0;
  let e = a;
  const lim = Math.min(M.MEM_SIZE, a + max);
  while (e < lim && M.mem[e] !== 0) e++;
  return Buffer.from(M.mem.buffer, M.mem.byteOffset + a, e - a).toString('latin1');
}
/** Write s and a NUL. */
function wstr(a, s) {
  a >>>= 0;
  for (let i = 0; i < s.length; i++) M.mem[a + i] = s.charCodeAt(i) & 0xFF;
  M.mem[a + s.length] = 0;
}
function rwstr(a, max = 0x8000) {
  a >>>= 0;
  let s = '';
  for (let i = 0; i < max; i++) { const c = M.dv.getUint16(a + 2 * i, true); if (!c) break; s += String.fromCharCode(c); }
  return s;
}
function wwstr(a, s) {
  a >>>= 0;
  for (let i = 0; i < s.length; i++) M.dv.setUint16(a + 2 * i, s.charCodeAt(i), true);
  M.dv.setUint16(a + 2 * s.length, 0, true);
}
const bytes = (a, n) => M.mem.subarray(a >>> 0, (a >>> 0) + n);
const fill = (a, n, v = 0) => M.mem.fill(v, a >>> 0, (a >>> 0) + n);
const put = (a, buf) => M.mem.set(buf, a >>> 0);

/** Map guest pages read/write (or with the given protection) so lifted code can access them. */
function map(a, n, prot = M.PROT_RW) { M.mapPages(a >>> 0, n, prot); }

module.exports = { M, r8, r16, r32, s32, w8, w16, w32, rstr, wstr, rwstr, wwstr, bytes, fill, put, map };
