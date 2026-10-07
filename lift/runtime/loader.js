'use strict';
// PE image loader: maps the user's rct.exe into guest memory as the Windows loader does
// (headers + sections at their RVAs, uninitialised tails zero), fills every IAT slot with a
// host magic address (HOST_BASE + 16*i, i = import index in import-descriptor order, then
// thunk order) and sets page protections from the section characteristics.

const fs = require('fs');
const C = require('./constants');
const M = require('./memory');

const EXPECTED_MD5 = '59e88bbcf3a6db7ea81c648a4afba935';

function parsePE(buf) {
  const u16 = (o) => buf.readUInt16LE(o), u32 = (o) => buf.readUInt32LE(o);
  if (u16(0) !== 0x5A4D) throw new Error('not an MZ executable');
  const pe = u32(0x3C);
  if (u32(pe) !== 0x4550) throw new Error('no PE signature');
  const nsec = u16(pe + 6), optSize = u16(pe + 20), opt = pe + 24;
  if (u16(opt) !== 0x10B) throw new Error('not a PE32 image');
  const h = {
    entry: u32(opt + 16), imageBase: u32(opt + 28), sectionAlign: u32(opt + 32),
    sizeOfImage: u32(opt + 56), sizeOfHeaders: u32(opt + 60),
    stackReserve: u32(opt + 72), stackCommit: u32(opt + 76),
    importRva: u32(opt + 96 + 8), importSize: u32(opt + 96 + 12),
  };
  const sections = [];
  for (let k = 0; k < nsec; k++) {
    const o = opt + optSize + 40 * k;
    sections.push({
      name: buf.toString('latin1', o, o + 8).replace(/\0+$/, ''),
      vsize: u32(o + 8), rva: u32(o + 12), rawSize: u32(o + 16), rawPtr: u32(o + 20),
      chars: u32(o + 36),
    });
  }
  return { h, sections };
}

// Load `exePath` into guest memory. Returns {entry, imports, sections, md5}.
// imports[i] = {index, dll, name, ordinal, key, iat, addr}; key = 'DLL!name' with the DLL name
// upper-cased (e.g. 'KERNEL32.DLL!GetVersion', ordinal imports as 'DSOUND.DLL!#1').
function loadImage(exePath, { checkMd5 = true } = {}) {
  const buf = fs.readFileSync(exePath);
  const md5 = require('crypto').createHash('md5').update(buf).digest('hex');
  if (checkMd5 && md5 !== EXPECTED_MD5) throw new Error(`${exePath}: md5 ${md5}, expected ${EXPECTED_MD5} (English v1.08.183)`);
  const { h, sections } = parsePE(buf);
  const base = h.imageBase;
  if (base !== C.IMAGE_BASE || base + h.sizeOfImage !== C.IMAGE_HI) throw new Error('unexpected image layout');

  // headers: read-only
  M.mem.fill(0, base, base + h.sizeOfImage);
  M.mem.set(buf.subarray(0, h.sizeOfHeaders), base);
  M.mapPages(base, h.sizeOfHeaders, M.PROT_R);
  const codeNames = new Set(C.CODE_SECTIONS);
  for (const s of sections) {
    const va = base + s.rva;
    const n = Math.min(s.rawSize, s.vsize);
    M.mem.set(buf.subarray(s.rawPtr, s.rawPtr + n), va);
    const span = Math.ceil(Math.max(s.vsize, 1) / h.sectionAlign) * h.sectionAlign;
    const W = (s.chars & 0x80000000) !== 0;
    let prot = M.PROT_R | (W ? M.PROT_W : 0);
    // Lifted code is translated ahead of time: a write into it would be self-modifying code,
    // which the scope study found never happens (docs/stage1-scope.md M3). Make it a fault.
    if (codeNames.has(s.name)) prot = M.PROT_R | M.PROT_CODE;
    M.mapPages(va, span, prot);
    const expect = C.SECTIONS[s.name];
    if (expect && (expect[0] !== va || expect[1] !== va + s.vsize)) throw new Error(`section ${s.name} not where expected`);
  }

  // imports
  const imports = [];
  let d = base + h.importRva;
  const r32 = (a) => M.dv.getUint32(a, true);
  for (;; d += 20) {
    const ilt = r32(d), nameRva = r32(d + 12), iatRva = r32(d + 16);
    if (!ilt && !nameRva && !iatRva) break;
    const dll = M.readCString(base + nameRva);
    let t = base + (ilt || iatRva), slot = base + iatRva;
    for (;; t += 4, slot += 4) {
      const e = r32(t);
      if (e === 0) break;
      let name = null, ordinal = null;
      if (e & 0x80000000) ordinal = e & 0xFFFF;
      else name = M.readCString(base + e + 2);
      const index = imports.length;
      const addr = (C.HOST_BASE + 16 * index) >>> 0;
      imports.push({ index, dll, name, ordinal, key: dll.toUpperCase() + '!' + (name !== null ? name : '#' + ordinal), iat: slot, addr });
    }
  }
  // fill the IAT (in .rdata, read-only to the guest; the loader writes it directly)
  for (const im of imports) M.dv.setUint32(im.iat, im.addr, true);
  return { entry: base + h.entry, imports, sections, md5, header: h };
}

module.exports = { loadImage, parsePE, EXPECTED_MD5 };
