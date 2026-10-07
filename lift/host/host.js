'use strict';
// The host: the Win32 + COM environment the lifted rct.exe runs in, reproducing the oracle's
// pinned environment (oracle/rcthook.c) and Wine's answers (wine-answers.js).
//
// Every import rct.exe calls has an implementation (kernel32.js, user32.js, gdi32.js, winmm.js,
// advapi32.js, media.js); every import it never calls in the corpus gets a stub that throws,
// naming the function, so that new code paths are noticed instead of silently mis-emulated.
const fs = require('fs');
const path = require('path');
const G = require('./guestmem');
const W = require('./wine-answers');
const { TraceWriter, TR, TRACE_VERSION } = require('./trace');
const { VirtualClock, VT_BASE } = require('./clock');
const { parseScript, ScriptError } = require('./script');
const { GameHooks, HostQuit } = require('./hooks');
const { AddressSpace, Heap } = require('./heap');
const { HandleTable } = require('./handles');
const { Vfs } = require('./vfs');

/** 64-bit build id of the lift: first 8 bytes of SHA-256 over the lift's sources (TR_BUILD). */
function buildId() {
  const crypto = require('crypto');
  const root = path.resolve(__dirname, '..');
  const files = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) { if (e.name !== 'test' && e.name !== '__pycache__') walk(f); } else if (/\.(js|py|json)$/.test(e.name)) files.push(f);
  } };
  walk(root);
  const h = crypto.createHash('sha256');
  for (const f of files) { h.update(path.relative(root, f)); h.update(fs.readFileSync(f)); }
  return h.digest().readBigUInt64LE(0);
}

class HostNotImplemented extends Error {
  constructor(name, detail) {
    super(`host: ${name} ${detail || 'is not implemented: rct.exe never called it in the corpus'}`);
    this.name = 'HostNotImplemented'; this.fn = name;
  }
}
/** A modal dialog or message box: the oracle ends the run with exit status 4. */
class HostDialog extends Error {
  constructor(what, text) { super(`${what}: ${text}`); this.name = 'HostDialog'; this.code = 4; }
}

// Guest memory the host hands out: [0x00A00000, MEM_SIZE). Wine-placed objects (C runtime heap,
// its small-block region, the DIB, the CSG1.DAT view) are reserved at their Wine addresses.
const ARENAS = [[0x00A00000, 0x05400000]];

class Host {
  /**
   * @param m     the machine (lift/runtime)
   * @param o     {exePath, gameDir, cdDir, scriptPath|scriptText, outDir, rt, quantum, chunks}
   */
  constructor(m, o) {
    this.m = m;
    this.rt = o.rt || require('../runtime');
    this.o = o;
    this.outDir = o.outDir;
    fs.mkdirSync(this.outDir, { recursive: true });
    this.logFd = fs.openSync(path.join(this.outDir, 'hook.log'), 'w');
    this.u8 = G.M.mem;
    this.u32 = new Uint32Array(G.M.mem.buffer, G.M.mem.byteOffset, G.M.mem.byteLength >>> 2);
    this.chunks = o.chunks !== undefined ? !!o.chunks : true;
    this.quantum = o.quantum !== undefined ? o.quantum >>> 0 : 1;
    this.W = W;
    this.lastError = 0;
    this.input = { keys: new Uint8Array(256), curX: W.CURSOR_START[0], curY: W.CURSOR_START[1],
      dmDx: 0, dmDy: 0, dmButtons: 0,          // fake DirectInput mouse (script dimouse)
      fileAnswer: null };                      // next common file dialog's answer (script file)
    this.space = new AddressSpace(ARENAS);
    this.handles = new HandleTable(W.HANDLES, Object.entries(W.STD_HANDLES).map(([, v]) => [v.h, { type: 'std', fileType: v.type }]));
    const repo = path.resolve(__dirname, '../..');
    this.vfs = new Vfs({
      gameDir: o.gameDir || path.join(repo, 'game/prefix/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon'),
      cdDir: o.cdDir || path.join(repo, 'game/cd'),
      overlayDir: path.join(this.outDir, 'overlay'),
    });
    this.defined = new Set();
    // functions whose return kind is void (oracle/apisig.txt), for the register pin after OS calls
    const { loadSigs } = require('./apitrace');
    this.voidFns = new Set([...loadSigs(fs.readFileSync(path.join(__dirname, '../../oracle/apisig.txt'), 'utf8')).sigs.values()]
      .filter((g) => g.ret.base === 'v').map((g) => g.name));
    this.osObjects = [];          // [ptr, iface] of COM objects handed to the game (osmap.txt)
    this.osVtables = [];          // [ptr, iface] of their vtables (osmap.txt "vtbl")
    this.onFrame = null;
  }

  // ------------------------------------------------------------------ logging
  log(s) { fs.writeSync(this.logFd, s + '\n'); }

  // ------------------------------------------------------------------ set-up
  install() {
    const o = this.o;
    this.log(`lift host: out=${this.outDir} realtime=0 quantum=${this.quantum}`);
    // rcthook.c opens trace.bin before reading the script: a fatal script leaves it empty
    this.trace = new TraceWriter(path.join(this.outDir, 'trace.bin'));
    let text = o.scriptText;
    if (text === undefined && o.scriptPath) {
      try { text = fs.readFileSync(o.scriptPath, 'latin1'); } catch (e) {
        this.log(`script: cannot open ${o.scriptPath}`);
        throw this.fatal('script unreadable', 0);
      }
    }
    try { this.script = parseScript(text || ''); } catch (e) {
      if (e instanceof ScriptError) throw this.fatal(e.why, e.line);
      throw e;
    }
    for (const l of this.script.log) this.log(l);
    this.log(`script: ${this.script.actions.length} actions from ${o.scriptPath || '(text)'}`);
    if (this.script.quantum !== undefined) this.quantum = this.script.quantum;   // script header overrides
    this.clock = new VirtualClock(this.script.seed !== undefined ? this.script.seed : VT_BASE, this.quantum);
    this.trace.rec(TR.HEADER, TRACE_VERSION, 0, this.quantum);
    if (TR.BUILD !== undefined) {
      const id = buildId();
      this.log(`lift host build ${id.toString(16).padStart(16, '0')}`);
      this.trace.rec(TR.BUILD, Number(id & 0xFFFFFFFFn), Number(id >> 32n), 1);   // producer 1: lift host
    }
    this.trace.rec(TR.NOTE, 0, 0, this.clock.vt);

    // the process heap holds what Wine keeps in process memory (command line, environment,
    // COM objects of the fake DirectInput, ...)
    this.processHeap = new Heap(this.space, 0, 0x100000);
    this.processHeap.handle = this.processHeap.chunks[0].lo;
    this.heaps = new Map([[this.processHeap.handle, this.processHeap]]);

    this.hooks = new GameHooks(this);
    this.hooks.install();

    const spike = (process.env.RCTHOOK_SPIKE || o.spike || '').split(',');
    const ist = spike.map((t) => /^istep=(\d+)(?::(\d+))?$/.exec(t)).find(Boolean);
    if (ist) {
      if (!spike.includes('regs')) throw new Error('RCTHOOK_SPIKE=istep: the lift host offers the register capture only (add ,regs)');
      const man = this.m.liftManifest;
      if (man && man.flag_opt) this.log('istep: WARNING: the lift computes only live flags; use a --no-flag-opt lift for register capture');
      const mapPath = o.mapPath || (man && man.map);
      const mapBlocks = mapPath ? new Set(JSON.parse(fs.readFileSync(mapPath, 'utf8')).blocks) : null;
      this.istep = { from: +ist[1], to: ist[2] !== undefined ? +ist[2] : +ist[1], mapBlocks, cap: null, done: false };
      this.log(`istep: ticks ${this.istep.from}..${this.istep.to}, map ${mapPath || '(all lifted blocks)'}`);
    }
    if (o.apitrace || spike.includes('apitrace')) {
      this.apitrace = new (require('./apitrace').ApiTrace)(this, path.join(this.outDir, 'apitrace.txt'));
    }
    for (const mod of ['./kernel32', './user32', './gdi32', './winmm', './advapi32', './media', './comdlg32']) require(mod).install(this);
    // every other import: a stub that names itself
    for (const im of this.m.imports) {
      if (this.defined.has(im.key)) continue;
      const key = im.key;
      this.m.bindImport(key, () => { throw new HostNotImplemented(key); });
    }
    this.enterAsWine();
    if (this.apitrace) this.apitrace.entry(this.m);
  }

  /** The main thread's registers and stack at the entry point, as Wine sets them up. */
  enterAsWine() {
    const m = this.m, E = W.ENTRY;
    G.map(E.STACK_LO, E.STACK_HI - E.STACK_LO);
    m.esp = E.esp;
    // the entry point's return address as Wine leaves it; returning there ends the process
    G.w32(m.esp, E.ret);
    m.specials.set(E.ret, (mm) => { throw new this.rt.GuestExit(mm.eax); });
    E.stack.forEach((v, i) => G.w32(m.esp + 4 + 4 * i, v));
    for (const r of ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']) m[r] = E[r];
    m.setEflags(E.eflags);
  }

  /** osmap.txt (oracle/README.md "Register capture"): the host's function values and COM objects. */
  writeOsmap() {
    const m = this.m;
    const L = ['# osmap 1'];
    for (let k = 0; k < m.hostTable.length; k++) {
      if (!m.hostTable[k]) continue;
      const im = m.imports[k];
      const nm = m.hostNames[k] || '?';
      L.push(`fn ${((this.rt.HOST_BASE + 16 * k) >>> 0).toString(16)} ${im ? im.iat.toString(16) : '0'} ${this.traceName(nm)}`);
    }
    for (const [p, iface] of this.osObjects) L.push(`obj ${p.toString(16)} ${iface}`);
    for (const [p, iface] of this.osVtables) L.push(`vtbl ${p.toString(16)} ${iface}`);
    fs.writeFileSync(path.join(this.outDir, 'osmap.txt'), L.join('\n') + '\n');
  }

  get frame() { return this.hooks.frame; }
  get tick() { return this.hooks.tick; }

  // ------------------------------------------------------------------ function definitions
  /**
   * Define the implementation of an import. `fn(...args)` gets the stack arguments (uint32) and
   * returns the value for eax (undefined: leave eax), or {eax, edx}. conv 'std' pops nargs.
   */
  def(key, nargs, fn, conv = 'std') {
    const impl = this.wrap(key, nargs, fn, conv);
    this.m.bindImport(key, impl);
    this.defined.add(this._norm(key));
    return impl;
  }
  _norm(key) { const i = key.indexOf('!'); return key.slice(0, i).toUpperCase() + key.slice(i); }
  /** The name a call is recorded under in the API trace (oracle/README.md "API trace"). */
  traceName(name) {
    if (name.includes('::')) return name;
    const im = this.m.importByKey.get(this._norm(name));
    if (im) return im.name !== null ? im.name : `${im.dll}#${im.ordinal}`;
    return name.slice(name.indexOf('!') + 1);
  }
  wrap(name, nargs, fn, conv = 'std') {
    let tname = null, isVoid = null;
    return (m) => {
      if (isVoid === null) { tname = tname || this.traceName(name); isVoid = this.voidFns.has(tname); }
      const at = this.apitrace ? this.apitrace.call(m, tname || (tname = this.traceName(name))) : null;
      const a = new Array(nargs);
      for (let i = 0; i < nargs; i++) a[i] = m.arg(i);
      const r = fn.apply(this, a);
      if (r !== undefined) {
        if (typeof r === 'object') { m.eax = r.eax >>> 0; if (r.edx !== undefined) m.edx = r.edx >>> 0; }
        else m.eax = r >>> 0;
      }
      // [pin] rcthook.c/apitrace.c: after every OS call the game sees ecx = edx = 0, eflags 0x202,
      // and eax = 0 after a void function (apisig.txt return kind v)
      m.ecx = 0; m.edx = 0;
      if (isVoid) m.eax = 0;
      m.setEflags(0x202);
      if (at) this.apitrace.ret(at, m.eax);
      if (conv === 'std') m.retStd(nargs); else m.retCdecl();
    };
  }
  /** A host function at a fresh host address (GetProcAddress results, COM methods). */
  hostFn(name, nargs, fn, conv = 'std') { return this.m.allocHost(name, this.wrap(name, nargs, fn, conv)); }

  /** Build a COM object: vtable of host functions in guest memory. methods: [[name, nargs, fn]] */
  comObject(iface, methods, extra = 0) {
    const vt = this.processHeap.alloc(4 * methods.length);
    methods.forEach(([name, nargs, fn], i) => G.w32(vt + 4 * i, this.hostFn(`${iface}::${name}`, nargs, fn)));
    const obj = this.processHeap.alloc(4 + extra);
    G.w32(obj, vt);
    this.osObjects.push([obj, iface]);
    this.osVtables.push([vt, iface]);
    return obj;
  }

  /** Call a stdcall guest callback with stack arguments; returns eax. Preserves nothing else. */
  callStd(addr, args) {
    const m = this.m;
    for (let i = args.length - 1; i >= 0; i--) m.push32(args[i] >>> 0);
    const r = m.callGuest(addr);
    return r.eax >>> 0;
  }
  /** Call a guest callback as Windows does: callee-saved registers (ebx, esi, edi, ebp) survive. */
  callback(addr, args, kind) {
    const m = this.m;
    const s = { ebx: m.ebx, esi: m.esi, edi: m.edi, ebp: m.ebp };
    const esp = m.esp;
    const at = this.apitrace && kind ? this.apitrace.cbEnter(kind, addr, esp, args) : null;
    const r = this.callStd(addr, args);
    if (at) this.apitrace.cbLeave(at, r);
    if (m.esp !== esp) throw new Error(`guest callback ${addr.toString(16)} left esp ${m.esp.toString(16)} (expected ${esp.toString(16)})`);
    m.ebx = s.ebx; m.esi = s.esi; m.edi = s.edi; m.ebp = s.ebp;
    return r;
  }

  // ------------------------------------------------------------------ guest memory from the host
  /** Copy a string into fresh process-heap memory; returns its address. */
  allocString(s) { const p = this.processHeap.alloc(s.length + 1); G.wstr(p, s); return p; }
  allocWString(s) { const p = this.processHeap.alloc(2 * s.length + 2); G.wwstr(p, s); return p; }

  // ------------------------------------------------------------------ run end
  fatal(why, line) {
    this.log(`FATAL: ${why} (script line ${line})`);
    const e = new HostQuit(3, why);
    return e;
  }
  dialogFatal(what, text) {
    this.log(`FATAL: ${what}: ${text || ''} (frame ${this.frame} tick ${this.tick})`);
    this.trace.flush();
    return new HostDialog(what, text || '');
  }

  /**
   * End of run. `exit`: the GuestExit code if the game exited, `error`: what ended the run
   * otherwise. Returns the process exit status (0: the script reached quit).
   */
  finish({ exit, error } = {}) {
    let status;
    if (error instanceof HostQuit) status = error.code;
    else if (error instanceof HostDialog) status = 4;
    else if (error) {
      this.log(`run ended by ${error.name || 'error'}: ${error.message} (frame ${this.frame} tick ${this.tick})`);
      status = 5;
    } else status = exit !== undefined ? 1 : 1;
    // TerminateProcess (quit, fatal script, modal dialog) runs no DllMain: only a process that
    // ends otherwise gets rcthook.c's DLL_PROCESS_DETACH record
    if (this.hooks && !this.hooks.quitting && !(error instanceof HostQuit) && !(error instanceof HostDialog) && this.trace && !this.trace.closed) {
      // rcthook.c DllMain(DLL_PROCESS_DETACH) without quit
      this.trace.rec(TR.END, this.hooks.frame, this.hooks.tick, this.hooks.rngDraws);
      this.log(`process detach at frame ${this.hooks.frame} tick ${this.hooks.tick}`);
    }
    if (this.trace) this.trace.close();
    if (this.apitrace) this.apitrace.close();
    if (this.istep && this.istep.cap) { this.istep.cap.stop(); this.istep.cap = null; }
    if (this.istep || this.apitrace) this.writeOsmap();
    fs.closeSync(this.logFd);
    return status;
  }
}

module.exports = { Host, HostNotImplemented, HostDialog, HostQuit };
