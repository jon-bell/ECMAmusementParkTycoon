'use strict';
// Game hooks and the script executor: a port of the "game hooks" and run_actions() of
// oracle/rcthook.c, producing the same trace records in the same order.
//
// Differences forced by the execution model (docs/stage1-design.md):
//   * an inline hook in the oracle saves every register and flag, calls C code and restores
//     them; here a hook runs before the block at its address and restores what it changed;
//   * `cmd`/`call` run the routine with callGuest (the oracle: call_asm from the hook);
//   * `load` pushes HOST_RETURN_LOAD and redirects eip to 0x43054E (the routine long-jumps to
//     the main loop on success, like the oracle's call_asm that never returns).
const fs = require('fs');
const path = require('path');
const G = require('./guestmem');
const { TR } = require('./trace');
const { recordState, STATE_LO, STATE_HI, STATE2_LO, STATE2_HI } = require('./statehash');
const { A, W_FRAME, W_TICK } = require('./script');

const A_RNG_STORE = 0x5DF42A, A_TICK = 0x43888E, A_FRAME = 0x4385D8, A_FRAME_BODY = 0x4386EC;
const A_DO_COMMAND = 0x426F56, A_NEW_GAME = 0x43054E;
const A_SRAND0 = 0x6E3B88, A_SRAND1 = 0x6E3B8C, A_TITLE = 0x628CB9;
const A_SCREEN_DPI = 0x99FB7C;

class HostQuit extends Error {
  constructor(code, why) { super(`run ended (exit ${code})${why ? ': ' + why : ''}`); this.name = 'HostQuit'; this.code = code; }
}

class GameHooks {
  /**
   * @param {object} h  the host: {m, trace, clock, log(fmt), outDir, chunks, script, u8, u32, rt, input}
   */
  constructor(h) {
    this.h = h;
    this.frame = 0; this.tick = 0; this.rngDraws = 0;
    this.loading = false; this.loadFrame = 0; this.quitting = false;
    this.nextAct = 0;
    this.lastMode = 0xFFFF;
    this.loadSaved = null;        // registers at the frame-body hook that started a load
    this.skipHookAt = -1;         // resume a hooked block once without its hook (failed load)
  }

  install() {
    const m = this.h.m;
    m.hooks.set(A_RNG_STORE, (m) => this.onRng(m));
    m.hooks.set(A_TICK, (m) => this.onTick(m));
    m.hooks.set(A_FRAME, (m) => this.onFrame(m));
    m.hooks.set(A_FRAME_BODY, (m) => this.onFrameBody(m));
    m.hooks.set(A_DO_COMMAND, (m) => this.onCommand(m));
    m.specials.set(this.h.rt.HOST_RETURN_LOAD, (m) => this.onLoadReturned(m));
  }

  onRng(m) {
    const caller = (G.r32(m.esp + 4) - 5) >>> 0;   // [esp] = saved ebx, [esp+4] = return address
    this.rngDraws++;
    this.h.trace.rec(TR.RNG, this.tick, caller, m.eax);
  }
  onTick(m) {
    if (this.skipHookAt === m.eip) { this.skipHookAt = -1; return undefined; }
    this.tick++;
    this.h.trace.rec(TR.TICK, this.tick, G.r32(A_SRAND0), G.r32(A_SRAND1));
    recordState(this.h.trace, TR.STATE, this.tick, this.h.u8, this.h.u32, this.h.chunks);
    if (this.h.istep) this.istepTick(m);
    return this.runActions(m, W_TICK);
  }
  onFrame(m) {
    if (this.loading) {   // the previous frame's load completed by long-jump
      this.loading = false;
      this.loadSaved = null;
      const sc = G.r16(0x8DBED2);
      this.h.trace.rec(TR.NOTE, this.tick, 3, sc);
      this.h.log(`scenario ${sc} loaded, frame ${this.frame} (title ticks before load: ${this.tick}); tick counter reset`);
      this.tick = 0;
      this.loadFrame = this.frame + 1;
    }
    this.frame++;
    this.h.trace.rec(TR.FRAME, this.frame, this.h.clock.vt, this.tick);
    if (this.h.onFrame) this.h.onFrame(this.frame);
  }
  onFrameBody(m) {
    if (this.skipHookAt === m.eip) { this.skipHookAt = -1; return undefined; }
    const mode = G.r16(0x99A500);
    if (mode !== this.lastMode) {
      this.h.log(`frame ${this.frame} tick ${this.tick}: [0x99A500] ${hx(this.lastMode)} -> ${hx(mode)}, scenario ${G.r16(0x8DBED2)}`);
      this.lastMode = mode;
    }
    return this.runActions(m, W_FRAME);
  }
  onCommand(m) {
    let caller = (G.r32(m.esp) - 5) >>> 0;
    if (caller < 0x401000 || caller >= 0x9BD000) caller = 0xFFFFFFFF;   // injected by the script
    this.h.trace.rec(TR.COMMAND, this.tick, (m.esi | (m.ebx & 0xff) << 8 | G.r8(0x5F4A6A) << 16) >>> 0, caller);
    this.h.trace.rec(TR.REGS_IN, m.eax, m.ebx, m.ecx);
    this.h.trace.rec(TR.REGS_IN2, m.edx, m.esi, m.edi);
    if (TR.REGS_IN3 !== undefined) this.h.trace.rec(TR.REGS_IN3, m.ebp, m.getEflags() & 0xCD5, 0);   // handlers receive ebp too
  }

  /**
   * Register capture over ticks A..B (RCTHOOK_SPIKE=istep=A:B,regs, as the oracle): starts in the
   * hook of tick A, a T record per tick before the tick's script actions, stops at tick B+1.
   * Lift side of the format: lift/runtime/capture.js (use a --no-flag-opt lift).
   */
  istepTick(m) {
    const s = this.h.istep;
    if (!s.cap && !s.done && this.tick === s.from) {
      s.cap = require('../runtime/capture').start(m, path.join(this.h.outDir, 'istep_regs.bin'), { mapBlocks: s.mapBlocks });
      this.h.log(`istep: on at tick ${this.tick}`);
    }
    if (s.cap) {
      if (this.tick > s.to) {
        const c = s.cap.stop(); s.cap = null; s.done = true;
        this.h.log(`istep: off at tick ${this.tick}: ${JSON.stringify(c)}`);
      } else s.cap.tick(this.tick);
    }
  }

  // ------------------------------------------------------------------ script actions
  /** Returns a new eip (load redirect) or undefined. */
  runActions(m, kind) {
    const acts = this.h.script.actions;
    const tr = this.h.trace;
    while (this.nextAct < acts.length) {
      const a = acts[this.nextAct];
      const now = a.whenKind === W_TICK ? this.tick : (this.frame - (a.rel ? this.loadFrame : 0)) >>> 0;
      if (a.whenKind !== kind || now < a.when) return undefined;
      if (a.action === A.LOAD && G.r8(A_TITLE)) return undefined;   // scenario select needs the intro over
      this.nextAct++;
      switch (a.action) {
        case A.QUIT: this.quit(); break;
        case A.DUMP: this.dump('script'); break;
        case A.SHOT: if (this.h.screenshot) this.h.screenshot(this.frame); break;
        case A.FB: this.fbDump(); break;
        case A.KEY:
          this.h.input.keys[a.arg & 255] = a.arg2 ? 0x80 : 0;
          tr.rec(TR.INPUT, this.tick, 1, (a.arg | a.arg2 << 16) >>> 0);
          break;
        case A.MOUSE: {
          const head = G.r32(0x5E91E4), next = (head + 1) & 0x3F;
          if (next === G.r32(0x5E91E8)) { this.h.log('mouse queue full'); break; }
          const e = 0x5F1CC0 + head * 12;
          G.w32(e, a.arg); G.w32(e + 4, a.arg2); G.w32(e + 8, a.r.eax);
          G.w32(0x5E91E4, next);
          this.h.input.curX = a.arg | 0; this.h.input.curY = a.arg2 | 0;
          tr.rec(TR.INPUT, this.tick, 4, (a.arg | a.arg2 << 16 | a.r.eax << 28) >>> 0);
          break;
        }
        case A.FILE:      // the answer of the next common file dialog
          this.h.input.fileAnswer = a.text;
          tr.rec(TR.INPUT, this.tick, 5, a.line);
          this.h.log(`line ${a.line}: next file dialog answers ${a.text}`);
          break;
        case A.CHAR:      // WM_CHAR through the message queue, as a key press would deliver it
        case A.MOVE: {    // WM_MOUSEMOVE (client coordinates, no buttons): the game's hover position
          const q = a.action === A.CHAR ? { m: 0x102, w: a.arg >>> 0, l: 1 } : { m: 0x200, w: 0, l: ((a.arg & 0xFFFF) | (a.arg2 & 0xFFFF) << 16) >>> 0 };
          if (!this.h.postScriptMessage(q)) { this.h.log(`line ${a.line}: message 0x${q.m.toString(16)} not delivered (no window or queue full)`); break; }
          if (a.action === A.CHAR) tr.rec(TR.INPUT, this.tick, 6, a.arg);
          else { tr.rec(TR.INPUT, this.tick, 8, q.l); this.h.input.curX = a.arg | 0; this.h.input.curY = a.arg2 | 0; }
          break;
        }
        case A.DIMOUSE: { // DirectInput mouse: deltas add up until the game reads them; buttons persist
          const I = this.h.input;
          I.dmDx = (I.dmDx + (a.arg | 0)) | 0; I.dmDy = (I.dmDy + (a.arg2 | 0)) | 0; I.dmButtons = a.r.eax & 0xF;
          tr.rec(TR.INPUT, this.tick, 7, ((a.arg & 0xFFF) | (a.arg2 & 0xFFF) << 12 | I.dmButtons << 24) >>> 0);
          break;
        }
        case A.CURSOR:
          this.h.input.curX = a.arg | 0; this.h.input.curY = a.arg2 | 0;
          tr.rec(TR.INPUT, this.tick, 2, (a.arg | a.arg2 << 16) >>> 0);
          break;
        case A.POKE:
          G.w8(a.arg, G.r8(a.arg) ^ (a.arg2 & 0xFF));
          tr.rec(TR.INPUT, this.tick, 3, a.arg);
          this.h.log(`poke [${hx(a.arg)}]^=${hx(a.arg2)} at tick ${this.tick}`);
          break;
        case A.LOAD: {
          // As the scenario-select window does (0x4304A7): ax = scenario, call the new-game
          // routine from inside the frame. call_asm loads eax..ebp from a zeroed regs_t.
          tr.rec(TR.LOAD, this.tick, a.arg, this.frame);
          this.h.log(`load scenario ${a.arg} at frame ${this.frame} tick ${this.tick}`);
          this.loading = true;
          this.loadSaved = { regs: m.regs(), kind, eip: m.eip };
          m.eax = a.arg >>> 0; m.ebx = 0; m.ecx = 0; m.edx = 0; m.esi = 0; m.edi = 0; m.ebp = 0; m.setEflags(0x202);
          // the oracle calls from inside its hook's C frames: the routine runs that much lower on
          // the stack (wine-answers.js HOOK_STACK)
          m.esp = (m.esp - (kind === W_TICK ? this.h.W.HOOK_STACK.callFromTick : this.h.W.HOOK_STACK.loadFromFrameBody)) >>> 0;
          m.push32(this.h.rt.HOST_RETURN_LOAD);
          return A_NEW_GAME;
        }
        case A.CMD: case A.CALL: {
          const r = a.r;
          const target = a.action === A.CMD ? A_DO_COMMAND : a.arg;
          const esi = a.action === A.CMD ? a.arg : r.esi;
          tr.rec(TR.INJECT, this.tick, a.action === A.CMD ? a.arg : target, a.line);
          tr.rec(TR.INJ_IN, r.eax, r.ebx, r.ecx);
          tr.rec(TR.INJ_IN2, r.edx, esi, r.edi);
          // flags at entry are defined: CF PF AF ZF SF DF OF from the script (default 0), IF set
          const eflags = ((r.eflags & 0xCD5) | 0x202) >>> 0;
          if (TR.INJ_IN3 !== undefined) tr.rec(TR.INJ_IN3, r.ebp, eflags & 0xCD5, 0);
          const saved = m.regs();
          m.esp = (m.esp - (kind === W_TICK ? this.h.W.HOOK_STACK.callFromTick : this.h.W.HOOK_STACK.loadFromFrameBody)) >>> 0;
          const out = m.callGuest(target, { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx, esi, edi: r.edi, ebp: r.ebp, eflags });
          m.setRegs(saved);
          tr.rec(TR.REGS_OUT, out.eax, out.ebx, out.ecx);
          tr.rec(TR.REGS_OUT2, out.edx, out.esi, out.edi);
          tr.rec(TR.REGS_OUT3, out.ebp, out.eflags, 0);
          this.h.log(`line ${a.line} ${a.action === A.CMD ? 'cmd' : 'call'} ${hx(a.action === A.CMD ? a.arg : target)} at frame ${this.frame} tick ${this.tick} -> ebx=${hx(out.ebx)}`);
          if (a.action === A.CMD && out.ebx === 0x80000000) this.h.log(`line ${a.line} cmd ${hx(a.arg)} failed: error string id [0x991EFC] = ${hx(G.r16(0x991EFC))}`);
          break;
        }
        default: throw new Error(`unknown action ${a.action}`);
      }
    }
    return undefined;
  }

  /** HOST_RETURN_LOAD reached: the new-game routine returned instead of long-jumping. */
  onLoadReturned(m) {
    const s = this.loadSaved;
    this.loading = false;
    this.loadSaved = null;
    const a = this.h.script.actions[this.nextAct - 1];
    this.h.trace.rec(TR.NOTE, this.tick, 2, a.arg);
    this.h.log(`load scenario ${a.arg} FAILED (returned, eflags ${hx(m.getEflags())})`);
    // The oracle's hook then continues run_actions() and returns to the hooked code with every
    // register and flag restored. Continue the remaining actions here, then resume the block.
    m.setRegs(s.regs);
    const r = this.runActions(m, s.kind);
    if (r !== undefined) return r;
    // resume the block the hook interrupted without running that hook a second time
    this.skipHookAt = s.eip;
    return s.eip;
  }

  quit() {
    this.quitting = true;
    recordState(this.h.trace, TR.FINAL, this.tick, this.h.u8, this.h.u32, this.h.chunks);
    this.h.trace.rec(TR.END, this.frame, this.tick, this.rngDraws);
    this.h.trace.flush();
    this.h.log(`quit at frame ${this.frame} tick ${this.tick}, rng draws ${this.rngDraws}, vt ${this.h.clock.vt}`);
    throw new HostQuit(0, 'quit');
  }
  dump(tag) {
    const name = `dump_${tag}_t${this.tick}.bin`;
    const fd = fs.openSync(path.join(this.h.outDir, name), 'w');
    fs.writeSync(fd, G.bytes(STATE_LO, STATE_HI - STATE_LO));
    fs.writeSync(fd, G.bytes(STATE2_LO, STATE2_HI - STATE2_LO));
    fs.closeSync(fd);
    this.h.log(`dump ${tag} tick ${this.tick} -> ${name}`);
  }
  /** The game's 8-bit screen buffer as a PGM of palette indices (rcthook.c fb_dump). */
  fbDump() {
    const bits = G.r32(A_SCREEN_DPI);
    const w = G.r16(A_SCREEN_DPI + 8), hgt = G.r16(A_SCREEN_DPI + 10), pitch = G.r16(A_SCREEN_DPI + 12);
    const s16 = (a) => (G.r16(a) << 16) >> 16;
    this.h.log(`fb: bits ${'0x' + bits.toString(16)} x ${s16(A_SCREEN_DPI + 4)} y ${s16(A_SCREEN_DPI + 6)} w ${w} h ${hgt} pitch ${pitch} zoom ${G.r16(A_SCREEN_DPI + 14)}`);
    if (!bits || !w || !hgt) return;
    const name = `fb_t${this.tick}_f${this.frame}.pgm`;
    const fd = fs.openSync(path.join(this.h.outDir, name), 'w');
    fs.writeSync(fd, Buffer.from(`P5\n${w} ${hgt}\n255\n`, 'latin1'));
    for (let y = 0; y < hgt; y++) fs.writeSync(fd, G.bytes(bits + y * (w + pitch), w));
    fs.closeSync(fd);
  }
}
const hx = (v) => '0x' + (v >>> 0).toString(16);

module.exports = { GameHooks, HostQuit, A_RNG_STORE, A_TICK, A_FRAME, A_FRAME_BODY, A_DO_COMMAND, A_NEW_GAME };
