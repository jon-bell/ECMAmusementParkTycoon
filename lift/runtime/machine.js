'use strict';
// The machine: registers, flags, dispatcher, host-call ABI and guest calls.
// Interface: lift/runtime/README.md. Design: docs/stage1-design.md ("Execution model").

const C = require('./constants');
const M = require('./memory');

const { IMAGE_LO, IMAGE_HI, HOST_BASE, HOST_RETURN, HOST_EXIT } = C;
const IMAGE_SPAN = IMAGE_HI - IMAGE_LO;
const HOST_RETURN_I32 = HOST_RETURN | 0;
const hex = M.hex;

class MissingBlock extends Error {
  constructor(eip, detail) {
    super(`MissingBlock: no lifted block at ${hex(eip)}${detail ? ' (' + detail + ')' : ''}`);
    this.name = 'MissingBlock'; this.eip = eip >>> 0;
  }
}
class HostMissing extends Error {
  constructor(eip, name) {
    super(`HostMissing: no host implementation for ${name || 'unknown host address'} (${hex(eip)})`);
    this.name = 'HostMissing'; this.eip = eip >>> 0; this.fn = name;
  }
}
// A CPU exception raised by a guest instruction. kind: 'DE' (divide error), 'BP' (int3),
// 'UD' (invalid opcode). m.eip is the faulting instruction and the register file is exactly
// the state before it, so the host can deliver it as a Win32 exception
// (EXCEPTION_INT_DIVIDE_BY_ZERO / EXCEPTION_INT_OVERFLOW for DE, EXCEPTION_BREAKPOINT for BP).
class GuestException extends Error {
  constructor(kind, eip, detail) {
    super(`GuestException ${kind} at ${hex(eip)}${detail ? ': ' + detail : ''}`);
    this.name = 'GuestException'; this.kind = kind; this.eip = eip >>> 0; this.detail = detail || '';
  }
}
// Thrown by the host (e.g. ExitProcess) or by a return to HOST_EXIT, to end the run.
class GuestExit extends Error {
  constructor(code) { super(`GuestExit(${code})`); this.name = 'GuestExit'; this.code = code >>> 0; }
}

// hooks: a Map<eip, fn(m)> that also keeps the dispatcher's per-address mark in sync.
class HookMap extends Map {
  constructor(machine) { super(); this._m = machine; }
  set(eip, fn) {
    eip >>>= 0;
    if (typeof fn !== 'function') throw new TypeError('hook must be a function');
    const i = eip - IMAGE_LO;
    if (i < 0 || i >= IMAGE_SPAN) throw new RangeError(`hook at ${hex(eip)}: outside the image`);
    const m = this._m;
    if (m.blocksFine && (m.blocksFine[i] === undefined || (m.hookable && !m.hookable.has(eip)))) {
      throw new Error(`hook at ${hex(eip)}: not a forced block start of this lift. Add it to lift/hooks.json and re-run the lifter.`);
    }
    this._m.hookMark[i] = 1;
    return super.set(eip, fn);
  }
  delete(eip) { eip >>>= 0; const i = eip - IMAGE_LO; if (i >= 0 && i < IMAGE_SPAN) this._m.hookMark[i] = 0; return super.delete(eip); }
  clear() { this._m.hookMark.fill(0); super.clear(); }
}

const FLAG_BITS = { cf: 0, pf: 2, af: 4, zf: 6, sf: 7, tf: 8, df: 10, of: 11 };

class Machine {
  constructor() {
    // registers: uint32 numbers. Field order is fixed here for a stable object shape.
    this.eax = 0; this.ecx = 0; this.edx = 0; this.ebx = 0;
    this.esp = 0; this.ebp = 0; this.esi = 0; this.edi = 0;
    this.eip = 0;
    this._blk = 0;   // int32: start of the block being executed (dispatcher bookkeeping)
    this._hookDone = -1;
    // flags: 0/1 numbers
    this.cf = 0; this.pf = 0; this.af = 0; this.zf = 0; this.sf = 0; this.tf = 0; this.df = 0; this.of = 0;
    this.xslot = 0;             // [disp32] slot of the last indirect call/jmp through memory, else 0
    this.capture = null;        // register capture (capture.js) when active
    this.fsBase = C.TEB_BASE;   // fs: segment base; every other segment is flat
    // x87 state (only what the C runtime's 15 x87 instructions need; see ops.js)
    this.fpu = { st: new Float64Array(8), top: 0, tag: 0xFF /* 1 = empty */, cw: 0x027F, sw: 0 };

    this.blocks = null;                       // dispatch table over [IMAGE_LO, IMAGE_HI): fn(m, eip) -> next eip
    this.blocksFine = null;                   // one function per block (instrumented loop)
    this.hookable = null;                     // with a region lift: the addresses hooks may use
    this.blockInsns = null;                   // Uint16Array: instructions per block (0 = no block)
    this.hookMark = new Uint8Array(IMAGE_SPAN);
    this.hooks = new HookMap(this);
    this.specials = new Map();                // eip -> fn(m) -> next eip (markers, continuations)
    this.hostTable = [];                      // host slot -> impl(m)
    this.hostNames = [];                      // host slot -> 'DLL!name' or a COM/callback name
    this.imports = [];                        // from the loader (see loader.js)
    this.importByKey = new Map();
    this.onException = null;                  // fn(m, GuestException) -> eip to resume, or throw
    this.depth = 0;                           // nesting of run loops (callGuest)
    // instrumentation (only with m.instrument = true): blocks executed, coverage, per-block callback
    this.instrument = false;
    this.blockCount = 0; this.insnCount = 0; this.hostCalls = 0;
    this.coverage = null;                     // Uint8Array over the image when enabled
    this.onBlock = null;                      // fn(m, eip) called before each block (instrumented loop)
    this.specials.set(HOST_EXIT, (m) => { throw new GuestExit(m.eax); });
  }

  // ---------------- flags ----------------
  getEflags() {
    return ((this.cf) | 2 | (this.pf << 2) | (this.af << 4) | (this.zf << 6) | (this.sf << 7) |
      (this.tf << 8) | 0x200 | (this.df << 10) | (this.of << 11)) >>> 0;
  }
  setEflags(v) {
    this.cf = v & 1; this.pf = (v >>> 2) & 1; this.af = (v >>> 4) & 1; this.zf = (v >>> 6) & 1;
    this.sf = (v >>> 7) & 1; this.tf = (v >>> 8) & 1; this.df = (v >>> 10) & 1; this.of = (v >>> 11) & 1;
  }

  // ---------------- stack ----------------
  push32(v) { const s = (this.esp - 4) >>> 0; M.w32(s, v >>> 0); this.esp = s; }
  pop32() { const v = M.r32(this.esp); this.esp = (this.esp + 4) >>> 0; return v; }
  push16(v) { const s = (this.esp - 2) >>> 0; M.w16(s, v & 0xFFFF); this.esp = s; }
  pop16() { const v = M.r16(this.esp); this.esp = (this.esp + 2) >>> 0; return v; }

  // ---------------- host-call ABI ----------------
  // In a host impl, esp points at the return address.
  arg(i) { return M.r32((this.esp + 4 + 4 * i) >>> 0); }
  retStd(nargs) { this.eip = this.pop32(); this.esp = (this.esp + 4 * nargs) >>> 0; }
  retCdecl() { this.eip = this.pop32(); }

  // Bind an implementation to an import ('KERNEL32.dll!GetVersion', DLL name case-insensitive).
  bindImport(key, impl) {
    const k = normKey(key);
    const im = this.importByKey.get(k);
    if (!im) throw new Error(`bindImport: rct.exe does not import ${key}`);
    this.hostTable[im.index] = impl;
    return im.addr;
  }
  // Allocate a new host address (COM methods, GetProcAddress results, callbacks).
  allocHost(name, impl) {
    const k = this.hostTable.length > this.imports.length ? this.hostTable.length : this.imports.length;
    if (k >= C.HOST_SLOTS) throw new Error('out of host slots');
    this.hostTable[k] = impl; this.hostNames[k] = name;
    return (HOST_BASE + 16 * k) >>> 0;
  }
  hostName(eip) { return this.hostNames[(eip - HOST_BASE) >>> 4]; }

  // ---------------- dispatch ----------------
  // special(eip): addresses that have no lifted block.
  special(eip) {
    const sp = this.specials.get(eip);
    if (sp !== undefined) return sp(this) >>> 0;
    if (eip >= HOST_BASE && (eip & 15) === 0) {
      const k = (eip - HOST_BASE) >>> 4;
      const impl = this.hostTable[k];
      if (impl === undefined) throw new HostMissing(eip, this.hostNames[k]);
      this.hostCalls++;
      if (this.capture !== null) this.capture.out(this.xslot, M.r32(this.esp));
      impl(this);
      if (this.eip === eip) throw new Error(`host impl ${this.hostNames[k]} did not return (call m.retStd(n) or m.retCdecl())`);
      return this.eip;
    }
    throw new MissingBlock(eip, this.describe(eip));
  }
  describe(eip) {
    for (const [n, [lo, hi]] of Object.entries(C.SECTIONS)) if (eip >= lo && eip < hi) return `inside ${n}`;
    if (eip >= HOST_BASE) return 'unallocated host address';
    return 'outside the image';
  }

  // Run from this.eip until eip reaches HOST_RETURN at this nesting level.
  run() {
    this.depth++;
    try {
      for (;;) {
        try {
          if ((this.instrument ? this._loopInstr() : this._loop()) === 0) return;
          continue;
        } catch (e) {
          if (e instanceof GuestException && this.onException) { this.eip = this.onException(this, e) >>> 0; continue; }
          if (e instanceof M.GuestFault && e.blockEip === undefined) { e.blockEip = this._blk >>> 0; this.eip = this._blk >>> 0; }
          else if (!(e instanceof GuestException) && !(e instanceof GuestExit) && !(e instanceof HostMissing) &&
                   !(e instanceof MissingBlock) && e.blockEip === undefined) e.blockEip = this._blk >>> 0;
          throw e;
        }
      }
    } finally { this.depth--; }
  }
  // The dispatch loops keep eip as an int32 (`| 0`): host addresses and markers are >= 2^31, and a
  // uint32 loop variable makes TurboFan deoptimise ("lost precision") on every host call.
  // Both loops return 0 at HOST_RETURN, or 1 to switch loops when m.instrument changed (checked
  // only after hooks and host calls, so it costs nothing per block). A switch right after a hook
  // that returned undefined must not run that hook again: _hookDone holds its eip.
  _loop() {
    const blocks = this.blocks, mark = this.hookMark;
    let eip = this.eip | 0;
    for (;;) {
      const i = eip - IMAGE_LO;                     // int32; negative for host addresses
      if (i >= 0 && i < IMAGE_SPAN) {
        if (mark[i] === 1) {
          if (this._hookDone === eip) this._hookDone = -1;
          else {
            this.eip = eip;
            const r = this.hooks.get(eip)(this);
            if (r !== undefined) { eip = r | 0; if (this.instrument) { this.eip = eip >>> 0; return 1; } continue; }
            if (this.instrument) { this._hookDone = eip; return 1; }
          }
        }
        const f = blocks[i];
        if (f !== undefined) { this._blk = eip; eip = f(this, eip) | 0; continue; }
      }
      this.eip = eip >>> 0;
      if (eip === HOST_RETURN_I32) return 0;
      eip = this.special(eip >>> 0) | 0;
      if (this.instrument) { this.eip = eip >>> 0; return 1; }
    }
  }
  _loopInstr() {
    const blocks = this.blocksFine, mark = this.hookMark, ni = this.blockInsns;
    let eip = this.eip | 0;
    for (;;) {
      const i = eip - IMAGE_LO;
      if (i >= 0 && i < IMAGE_SPAN) {
        if (mark[i] === 1) {
          if (this._hookDone === eip) this._hookDone = -1;
          else {
            this.eip = eip;
            const r = this.hooks.get(eip)(this);
            if (r !== undefined) { eip = r | 0; if (!this.instrument) { this.eip = eip >>> 0; return 1; } continue; }
            if (!this.instrument) { this._hookDone = eip; return 1; }
          }
        }
        const f = blocks[i];
        if (f !== undefined) {
          if (this.onBlock !== null) { this.eip = eip; this.onBlock(this, eip); }
          this.blockCount++; this.insnCount += ni[i];
          const cov = this.coverage;
          if (cov !== null) cov[i] = 1;
          this._blk = eip; eip = f(this) | 0; continue;
        }
      }
      this.eip = eip >>> 0;
      if (eip === HOST_RETURN_I32) return 0;
      eip = this.special(eip >>> 0) | 0;
      if (!this.instrument) { this.eip = eip >>> 0; return 1; }
    }
  }

  // Call guest code at addr with registers set from `regs` (eax..edi, ebp, esp, eflags).
  // Pushes HOST_RETURN, runs a nested dispatch loop until it is reached, restores this.eip and
  // returns the register file and flags. Saves nothing else (design: callers save what they need).
  callGuest(addr, regs) {
    if (regs) for (const k of Object.keys(regs)) {
      if (k === 'eflags') this.setEflags(regs[k]);
      else if (k in REGS) this[k] = regs[k] >>> 0;
      else throw new Error(`callGuest: unknown register ${k}`);
    }
    const saved = this.eip;
    this.push32(HOST_RETURN);
    this.eip = addr >>> 0;
    this.run();
    this.eip = saved;
    return this.regs();
  }
  regs() {
    return { eax: this.eax, ecx: this.ecx, edx: this.edx, ebx: this.ebx, esp: this.esp, ebp: this.ebp,
      esi: this.esi, edi: this.edi, eip: this.eip, eflags: this.getEflags() };
  }
  setRegs(r) {
    for (const k of Object.keys(r)) {
      if (k === 'eflags') this.setEflags(r[k]); else if (k === 'eip' || k in REGS) this[k] = r[k] >>> 0;
      else throw new Error(`setRegs: unknown register ${k}`);
    }
  }

  // ---------------- setup ----------------
  installImports(imports) {
    this.imports = imports;
    for (const im of imports) {
      this.hostNames[im.index] = im.key;
      this.importByKey.set(im.key, im);
    }
  }
  // Prepare the main thread: stack, TEB, entry registers. The host may adjust after this.
  initThread(entry) {
    M.mapPages(C.STACK_LO, C.STACK_HI - C.STACK_LO, M.PROT_RW);
    M.mapPages(C.TEB_BASE, 0x1000, M.PROT_RW);
    M.mem.fill(0, C.TEB_BASE, C.TEB_BASE + 0x1000);
    const t = C.TEB_BASE;
    M.dv.setUint32(t + 0x00, 0xFFFFFFFF, true);   // ExceptionList: end of SEH chain
    M.dv.setUint32(t + 0x04, C.STACK_HI, true);   // StackBase
    M.dv.setUint32(t + 0x08, C.STACK_LO, true);   // StackLimit
    M.dv.setUint32(t + 0x18, t, true);            // Self
    this.eax = this.ecx = this.edx = this.ebx = this.esi = this.edi = this.ebp = 0;
    this.setEflags(0x202);
    this.esp = C.STACK_INIT;
    this.push32(HOST_EXIT);
    this.eip = entry >>> 0;
  }
  // Coverage / counting instrumentation.
  enableInstrumentation({ coverage = true } = {}) {
    this.instrument = true;
    if (coverage && !this.coverage) this.coverage = new Uint8Array(IMAGE_SPAN);
  }
}
const REGS = { eax: 1, ecx: 1, edx: 1, ebx: 1, esp: 1, ebp: 1, esi: 1, edi: 1 };
function normKey(key) { const i = key.indexOf('!'); return key.slice(0, i).toUpperCase() + key.slice(i); }

module.exports = { Machine, MissingBlock, HostMissing, GuestException, GuestExit, HookMap, FLAG_BITS, normKey };
