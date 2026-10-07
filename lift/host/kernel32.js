'use strict';
// KERNEL32: files, find, mapping, memory, process start-up, NLS, time pins, modules.
const fs = require('fs');
const G = require('./guestmem');
const { TR } = require('./trace');
const { buildFindSet, putFind } = require('./findfile');
const { Heap, MEM_COMMIT, MEM_RESERVE } = require('./heap');
const { HostNotImplemented } = require('./host');

const INVALID_HANDLE_VALUE = 0xFFFFFFFF;
const E = { FILE_NOT_FOUND: 2, PATH_NOT_FOUND: 3, ACCESS_DENIED: 5, INVALID_HANDLE: 6, NO_MORE_FILES: 18,
  FILE_EXISTS: 80, INVALID_PARAMETER: 87, NEGATIVE_SEEK: 131, ALREADY_EXISTS: 183, PROC_NOT_FOUND: 127, MOD_NOT_FOUND: 126 };
const GENERIC_WRITE = 0x40000000;
const CSG1_VIEW = 0x03C80000;       // where Wine mapped CSG1.DAT (docs/stage1-scope.md M6)

function install(H) {
  const W = H.W;
  const K = (n) => 'KERNEL32.DLL!' + n;
  const hx = (v) => '0x' + (v >>> 0).toString(16);
  const setErr = (e) => { H.lastError = e; };

  // ---------------------------------------------------------------- time (oracle pins)
  H.def(K('GetTickCount'), 0, () => H.clock.query());
  H.def(K('Sleep'), 1, (ms) => { H.clock.sleep(ms); H.log(`Sleep(${ms}) frame ${H.frame}`); });
  H.def(K('GetSystemTime'), 1, (p) => {
    const t = H.clock.systemTime();
    [t.wYear, t.wMonth, t.wDayOfWeek, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds].forEach((v, i) => G.w16(p + 2 * i, v));
  });

  // ---------------------------------------------------------------- files
  const files = H.files = { viewNext: CSG1_VIEW };
  H.def(K('CreateFileA'), 7, (pname, access, share, sa, disp, flags, tmpl) => {
    const name = G.rstr(pname);
    const ret = G.r32(H.m.esp);                      // the caller's return address (rcthook.c)
    const h = createFile(name, access, disp);
    H.log(`CreateFileA(${name}, ${hx(access)}, disp ${disp}) from ${hx(ret)} frame ${H.frame} -> ${h === INVALID_HANDLE_VALUE ? 'ffffffff' : h.toString(16).padStart(8, '0')}`);
    H.trace.rec(TR.FILE, H.tick, ret, h !== INVALID_HANDLE_VALUE ? 1 : 0);
    return h;
  });
  function createFile(name, access, disp) {
    const v = H.vfs;
    const r = v.resolve(name);
    const want = (access & GENERIC_WRITE) !== 0;
    const exists = r.node !== null;
    if (!r.parentOk) { setErr(E.PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if (exists && r.node.isDir) { setErr(E.ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    // dispositions: 1 CREATE_NEW, 2 CREATE_ALWAYS, 3 OPEN_EXISTING, 4 OPEN_ALWAYS, 5 TRUNCATE_EXISTING
    if (!exists && (disp === 3 || disp === 5)) { setErr(E.FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if (exists && disp === 1) { setErr(E.FILE_EXISTS); return INVALID_HANDLE_VALUE; }
    const writable = want || disp === 1 || disp === 2 || disp === 4 || disp === 5;
    let host;
    if (writable && (want || !exists)) {
      if (!v.inGameDir(r.drive, r.names)) { setErr(E.ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
      host = v.overlayPath(r.names);
      v.ensureOverlayParents(r.names);
      const truncate = disp === 2 || disp === 5;
      if (exists && r.node.layer !== 'overlay' && !truncate) fs.copyFileSync(r.node.host, host);
      if (truncate || !exists) fs.writeFileSync(host, Buffer.alloc(0));
      v.whiteout.delete(v.gameKey(r.names));
    } else host = r.node.host;
    const fd = fs.openSync(host, want ? 'r+' : 'r');
    setErr(exists && (disp === 2 || disp === 4) ? E.ALREADY_EXISTS : 0);
    return H.handles.alloc({ type: 'file', fd, host, pos: 0, name, write: want });
  }
  const fileOf = (h) => { const o = H.handles.get(h); return o && o.type === 'file' ? o : null; };
  H.def(K('ReadFile'), 5, (h, buf, n, pread, ovl) => {
    const f = fileOf(h);
    if (!f) { setErr(E.INVALID_HANDLE); if (pread) G.w32(pread, 0); return 0; }
    const got = n ? fs.readSync(f.fd, G.bytes(buf, n), 0, n, f.pos) : 0;
    f.pos += got;
    if (pread) G.w32(pread, got);
    return 1;
  });
  H.def(K('WriteFile'), 5, (h, buf, n, pw, ovl) => {
    const o = H.handles.get(h);
    if (o && o.type === 'std') {   // stdout/stderr: kept beside the run (never compared)
      fs.appendFileSync(require('path').join(H.outDir, 'stdout.txt'), Buffer.from(G.bytes(buf, n)));
      if (pw) G.w32(pw, n);
      return 1;
    }
    const f = fileOf(h);
    if (!f || !f.write) { setErr(f ? E.ACCESS_DENIED : E.INVALID_HANDLE); if (pw) G.w32(pw, 0); return 0; }
    const put = fs.writeSync(f.fd, G.bytes(buf, n), 0, n, f.pos);
    f.pos += put;
    if (pw) G.w32(pw, put);
    return 1;
  });
  H.def(K('SetFilePointer'), 4, (h, lo, phi, method) => {
    const f = fileOf(h);
    if (!f) { setErr(E.INVALID_HANDLE); return 0xFFFFFFFF; }
    const dist = phi ? G.s32(phi) * 4294967296 + lo : (lo | 0);
    const base = method === 0 ? 0 : method === 1 ? f.pos : fs.fstatSync(f.fd).size;
    const np = base + dist;
    if (np < 0) { setErr(E.NEGATIVE_SEEK); return 0xFFFFFFFF; }
    f.pos = np;
    if (phi) G.w32(phi, Math.floor(np / 4294967296));
    setErr(0);
    return np >>> 0;
  });
  H.def(K('CloseHandle'), 1, (h) => {
    if (h === 0xFFFFFFFF || h === 0xFFFFFFFE) return 1;   // pseudo handles
    const o = H.handles.get(h);
    if (!o) { setErr(E.INVALID_HANDLE); return 0; }
    if (o.type === 'file') fs.closeSync(o.fd);
    if (o.type === 'std') return 1;
    H.handles.free(h);
    return 1;
  });
  H.def(K('GetFileType'), 1, (h) => {
    const o = H.handles.get(h);
    if (!o) { setErr(E.INVALID_HANDLE); return 0; }
    return o.type === 'std' ? o.fileType : 1;
  });
  H.def(K('CreateFileMappingA'), 6, (hf, sa, prot, hi, lo, pname) => {
    const f = fileOf(hf);
    if (!f) { setErr(E.INVALID_HANDLE); return 0; }
    const size = hi || lo ? hi * 4294967296 + lo : fs.fstatSync(f.fd).size;
    setErr(0);
    return H.handles.alloc({ type: 'mapping', host: f.host, size, prot });
  });
  H.def(K('MapViewOfFile'), 5, (hm, access, offHi, offLo, n) => {
    const o = H.handles.get(hm);
    if (!o || o.type !== 'mapping') { setErr(E.INVALID_HANDLE); return 0; }
    const off = offHi * 4294967296 + offLo;
    const len = n || o.size - off;
    const base = files.viewNext;
    const span = Math.ceil(len / 0x10000) * 0x10000;
    if (H.space.reserve(span, base, 'view') !== base) throw new Error(`MapViewOfFile: cannot place a view at ${hx(base)}`);
    const fd = fs.openSync(o.host, 'r');
    fs.readSync(fd, G.bytes(base, len), 0, len, off);
    fs.closeSync(fd);
    G.map(base, Math.ceil(len / 0x1000) * 0x1000, G.M.PROT_R);
    files.viewNext = base + span;
    H.log(`MapViewOfFile(${o.host}) -> ${hx(base)} (${len} bytes)`);
    return base;
  });

  // ---------------------------------------------------------------- find (rcthook.c pins)
  const finds = new Map();
  // [pin] rcthook.c: search handles 0x46490000 + 4*slot, lowest free of 16 slots (the game
  // keeps the handle in DATASEG at 0x5F9427)
  const findHandle = () => { for (let k = 0; k < 16; k++) { const h = 0x46490000 + 4 * k; if (!finds.has(h)) return h; } return 0; };
  H.def(K('FindFirstFileA'), 2, (ppat, out) => {
    const pat = G.rstr(ppat);
    const v = H.vfs;
    const p = v.parse(pat);
    const mask = p.parts.length ? p.parts[p.parts.length - 1] : '';
    const dir = v.resolve(p.drive + ':\\' + p.parts.slice(0, -1).join('\\'));
    let set = [];
    if (!dir.node || !dir.node.isDir) setErr(E.PATH_NOT_FOUND);
    else {
      set = buildFindSet(v.list(dir.drive, dir.names), mask, p.drive === 'D');
      if (!set.length) setErr(E.FILE_NOT_FOUND);
    }
    if (!set.length) { H.log(`FindFirstFileA(${pat}) frame ${H.frame} -> (none) []`); return INVALID_HANDLE_VALUE; }
    H.log(`FindFirstFileA(${pat}) frame ${H.frame} -> ${set[0].name} [${set[0].alt}]`);
    putFind(G, out, set[0]);
    const h = findHandle();
    if (!h) { H.log('FindFirstFileA: no free search slot'); setErr(4); return INVALID_HANDLE_VALUE; }
    finds.set(h, { set, i: 1 });
    return h;
  });
  H.def(K('FindNextFileA'), 2, (h, out) => {
    const s = finds.get(h);
    if (!s) { setErr(E.INVALID_HANDLE); return 0; }
    if (s.i >= s.set.length) { setErr(E.NO_MORE_FILES); return 0; }
    putFind(G, out, s.set[s.i++]);
    return 1;
  });
  H.def(K('FindClose'), 1, (h) => { if (finds.delete(h)) return 1; setErr(E.INVALID_HANDLE); return 0; });
  H.def(K('GetDiskFreeSpaceA'), 5, (root, spc, bps, freec, totc) => {   // [pin]
    const d = W.DISK_FREE;
    G.w32(spc, d.sectorsPerCluster); G.w32(bps, d.bytesPerSector); G.w32(freec, d.freeClusters); G.w32(totc, d.totalClusters);
    return 1;
  });

  // ---------------------------------------------------------------- memory
  let heapsCreated = 0;
  H.def(K('HeapCreate'), 3, (opts, init, max) => {
    const wh = W.HEAPS[heapsCreated++] || {};
    const hp = new Heap(H.space, 0, Math.max(init, 0x10000), { at: wh.at, first: wh.first, size: wh.size });
    hp.handle = hp.chunks[0].lo;
    H.heaps.set(hp.handle, hp);
    return hp.handle;
  });
  H.def(K('HeapAlloc'), 3, (h, flags, size) => {
    const hp = H.heaps.get(h);
    if (!hp) throw new Error(`HeapAlloc: unknown heap ${hx(h)}`);
    return hp.alloc(size, flags);
  });
  H.def(K('HeapFree'), 3, (h, flags, p) => {
    const hp = H.heaps.get(h);
    if (!hp || !p) return p ? 0 : 1;
    return hp.free(p) ? 1 : 0;
  });
  let reservations = 0;
  H.def(K('VirtualAlloc'), 4, (addr, size, type, prot) => {
    let base = addr;
    if (!addr || (type & MEM_RESERVE)) {
      base = H.space.reserve(size, addr || W.VIRTUAL_ALLOCS[reservations++] || undefined, 'virtual');
      if (!base) { setErr(8); return 0; }
    }
    if (type & MEM_COMMIT) {
      if (!H.space.commit(base, size)) { setErr(487); return 0; }
      return Math.floor(base / 0x1000) * 0x1000;
    }
    return base;
  });
  H.def(K('GlobalMemoryStatus'), 1, (p) => { W.MEMORY_STATUS.forEach((v, i) => G.w32(p + 4 * i, v)); });   // [pin]

  // ---------------------------------------------------------------- process, version, system
  const cmdline = H.allocString(W.COMMAND_LINE);
  H.def(K('GetCommandLineA'), 0, () => cmdline);
  H.def(K('GetVersion'), 0, () => W.VERSION);
  H.def(K('GetVersionExA'), 1, (p) => {
    const size = G.r32(p);
    if (size !== 0x94 && size !== 0x9c) { setErr(122); return 0; }
    const v = W.OSVERSION;
    G.w32(p + 4, v.major); G.w32(p + 8, v.minor); G.w32(p + 12, v.build); G.w32(p + 16, v.platform);
    G.wstr(p + 20, v.csd);
    return 1;
  });
  H.def(K('GetSystemInfo'), 1, (p) => { G.put(p, Uint8Array.from(W.SYSTEM_INFO)); });
  const isFeature = H.hostFn('KERNEL32.DLL!IsProcessorFeaturePresent', 1, (n) => (W.PROCESSOR_FEATURES.includes(n) ? 1 : 0));
  const startup = { desktop: H.allocString(W.STARTUP_INFO.desktop), title: H.allocString(W.STARTUP_INFO.title) };
  H.def(K('GetStartupInfoA'), 1, (p) => {
    G.fill(p, 0x44, 0);
    G.w32(p, 0x44); G.w32(p + 8, startup.desktop); G.w32(p + 12, startup.title);
    G.w16(p + 48, W.STARTUP_INFO.showWindow);
    G.w32(p + 56, 0xFFFFFFFF); G.w32(p + 60, 0xFFFFFFFF); G.w32(p + 64, 0xFFFFFFFF);
  });
  H.def(K('GetStdHandle'), 1, (n) => {
    const s = W.STD_HANDLES[n >>> 0];
    if (!s) { setErr(E.INVALID_HANDLE); return INVALID_HANDLE_VALUE; }
    return s.h;
  });
  H.def(K('SetHandleCount'), 1, (n) => n);
  let errorMode = 0;
  H.def(K('SetErrorMode'), 1, (mode) => { const o = errorMode; errorMode = mode; return o; });
  // [pin] rcthook.c ENV_BLOCK: GetEnvironmentStrings(W) return a fixed block (A and W, double-NUL
  // terminated); FreeEnvironmentStrings* of it return TRUE.
  const env = W.ENV_BLOCK;
  const envW = H.allocWString(env + '\0'), envA = H.allocString(env + '\0');
  H.def(K('GetEnvironmentStringsW'), 0, () => envW);
  H.def(K('GetEnvironmentStrings'), 0, () => envA);
  H.def(K('FreeEnvironmentStringsW'), 1, (p) => (p === envW ? 1 : 0));
  H.def(K('FreeEnvironmentStringsA'), 1, (p) => (p === envA ? 1 : 0));
  H.def(K('GetModuleFileNameA'), 3, (hmod, buf, n) => {
    if (hmod && hmod !== 0x400000) { setErr(E.MOD_NOT_FOUND); return 0; }
    const s = W.MODULE_FILE_NAME;
    if (n === 0) return 0;
    const k = Math.min(s.length, n - 1);
    G.wstr(buf, s.slice(0, k));
    if (s.length >= n) setErr(122);
    return k;
  });
  // modules: rct.exe, and the DLLs the game resolves functions from by name
  const MODULES = W.MODULES;
  const procs = {
    'KERNEL32.DLL': { IsProcessorFeaturePresent: isFeature },
    'DDRAW.DLL': {},
  };
  H.ddrawProcs = procs['DDRAW.DLL'];
  const modName = (s) => { let n = s.toUpperCase().replace(/^.*[\\/]/, ''); if (!n.includes('.')) n += '.DLL'; return n; };
  H.def(K('GetModuleHandleA'), 1, (p) => {
    if (!p) return 0x400000;
    const n = modName(G.rstr(p));
    if (n === 'RCT.EXE') return 0x400000;
    if (MODULES[n] && n !== 'DDRAW.DLL') return MODULES[n];
    setErr(E.MOD_NOT_FOUND); return 0;
  });
  H.def(K('LoadLibraryA'), 1, (p) => {
    const n = modName(G.rstr(p));
    if (MODULES[n]) return MODULES[n];
    H.log(`LoadLibraryA(${G.rstr(p)}): not available`);
    setErr(E.MOD_NOT_FOUND); return 0;
  });
  H.def(K('GetProcAddress'), 2, (hmod, pname) => {
    const mod = Object.keys(MODULES).find((k) => MODULES[k] === hmod);
    const name = pname >>> 16 ? G.rstr(pname) : '#' + pname;
    const f = mod && procs[mod][name];
    if (!f) { H.log(`GetProcAddress(${mod || hx(hmod)}!${name}) -> NULL`); setErr(E.PROC_NOT_FOUND); return 0; }
    return f;
  });
  // priorities (the frame loop raises and restores them every frame; values stay in .data)
  let prioClass = 0x20, threadPrio = 0;
  H.def(K('GetCurrentProcess'), 0, () => 0xFFFFFFFF);
  H.def(K('GetCurrentThread'), 0, () => 0xFFFFFFFE);
  H.def(K('GetPriorityClass'), 1, () => prioClass);
  H.def(K('SetPriorityClass'), 2, (h, c) => { prioClass = c; return 1; });
  H.def(K('GetThreadPriority'), 1, () => threadPrio);
  H.def(K('SetThreadPriority'), 2, (h, p) => { threadPrio = p | 0; return 1; });
  // named mutexes: the single-instance check
  const mutexes = new Map();
  H.def(K('OpenMutexA'), 3, (acc, inh, pname) => {
    const n = pname ? G.rstr(pname) : '';
    if (!mutexes.has(n)) { setErr(E.FILE_NOT_FOUND); return 0; }
    return H.handles.alloc({ type: 'mutex', name: n });
  });
  H.def(K('CreateMutexA'), 3, (sa, owner, pname) => {
    const n = pname ? G.rstr(pname) : '';
    const existed = mutexes.has(n);
    mutexes.set(n, true);
    setErr(existed ? E.ALREADY_EXISTS : 0);
    return H.handles.alloc({ type: 'mutex', name: n });
  });
  H.def(K('GetComputerNameA'), 2, (buf, pn) => { G.wstr(buf, W.COMPUTER_NAME); G.w32(pn, W.COMPUTER_NAME.length); return 1; });  // [pin]
  H.def(K('ExitProcess'), 1, (code) => { throw new H.rt.GuestExit(code); });

  // ---------------------------------------------------------------- NLS (code page 1252)
  const N = W.NLS;
  const rev = new Map();
  N.CP1252.forEach((w, b) => { if (!rev.has(w)) rev.set(w, b); });
  const toAnsi = (w) => (rev.has(w) ? [rev.get(w), false] : N.BEST_FIT[w] !== undefined ? [N.BEST_FIT[w], false] : [0x3f, true]);
  const fromAnsi = (b) => N.CP1252[b];
  const wIndex = new Map(N.CP1252.map((w, b) => [w, b]));
  const mapCase = (w, upper) => {
    const b = wIndex.get(w);
    if (b !== undefined) return (upper ? N.UPPER : N.LOWER)[b];
    const s = String.fromCharCode(w), t = upper ? s.toUpperCase() : s.toLowerCase();
    return t.length === 1 ? t.charCodeAt(0) : w;
  };
  H.def(K('GetACP'), 0, () => W.ACP);
  H.def(K('GetCPInfo'), 2, (cp, p) => {
    if (cp !== 0 && cp !== 1252 && cp !== 3) { setErr(E.INVALID_PARAMETER); return 0; }
    G.put(p, Uint8Array.from(W.CPINFO));
    return 1;
  });
  H.def(K('MultiByteToWideChar'), 6, (cp, flags, src, n, dst, dn) => {
    const len = n === 0xFFFFFFFF ? G.rstr(src).length + 1 : n;
    if (dn === 0) return len;
    if (dn < len) { setErr(122); return 0; }
    for (let i = 0; i < len; i++) G.w16(dst + 2 * i, fromAnsi(G.r8(src + i)));
    return len;
  });
  H.def(K('WideCharToMultiByte'), 8, (cp, flags, src, n, dst, dn, pdef, pused) => {
    let len = n;
    if (n === 0xFFFFFFFF) { len = 0; while (G.r16(src + 2 * len)) len++; len++; }
    let used = false;
    if (dn === 0) { if (pused) G.w32(pused, 0); return len; }
    if (dn < len) { setErr(122); return 0; }
    for (let i = 0; i < len; i++) {
      const [b, d] = toAnsi(G.r16(src + 2 * i));
      if (d) used = true;
      G.w8(dst + i, d && pdef ? G.r8(pdef) : b);
    }
    if (pused) G.w32(pused, used ? 1 : 0);
    return len;
  });
  H.def(K('LCMapStringW'), 6, (lcid, flags, src, n, dst, dn) => {
    let len = n;
    if ((n | 0) === -1) { len = 0; while (G.r16(src + 2 * len)) len++; len++; }
    if (flags & ~0x300) throw new HostNotImplemented('LCMapStringW', `flags ${hx(flags)} are not implemented`);
    if (dn === 0) return len;
    if (dn < len) { setErr(122); return 0; }
    for (let i = 0; i < len; i++) {
      let w = G.r16(src + 2 * i);
      if (flags & 0x200) w = mapCase(w, true); else if (flags & 0x100) w = mapCase(w, false);
      G.w16(dst + 2 * i, w);
    }
    return len;
  });
  H.def(K('GetStringTypeW'), 4, (type, src, n, out) => {
    let len = n;
    if ((n | 0) === -1) { len = 0; while (G.r16(src + 2 * len)) len++; len++; }
    const tab = type === 1 ? N.CTYPE1 : type === 2 ? N.CTYPE2 : type === 4 ? N.CTYPE3 : null;
    if (!tab) { setErr(1004); return 0; }
    for (let i = 0; i < len; i++) {
      const w = G.r16(src + 2 * i), b = wIndex.get(w);
      if (b === undefined) throw new HostNotImplemented('GetStringTypeW', `for U+${w.toString(16)} (outside code page 1252) is not measured`);
      G.w16(out + 2 * i, tab[b]);
    }
    return 1;
  });
}

module.exports = { install, INVALID_HANDLE_VALUE };
