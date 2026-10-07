'use strict';
// Register capture, lift side (oracle/README.md "Register capture", header flags 0):
//   R at every entry to a lifted block that is a block start of the code map (registers before
//     the block's first instruction, eflags = getEflags()),
//   W for every guest store (size 1/2/4; 8-byte stores split), in program order,
//   O when dispatching to a host function (the [disp32] slot of the call/jmp, else 0; return address),
//   T from the host's tick hook (m.capture.tick(n)).
// Compare with `tools/stepdiff.py diff ORACLE LIFT`. Use a lift built with --no-flag-opt
// (out/lift-ref): the optimised lift leaves dead flags stale at block entries.
//
//   const cap = require('./capture').start(m, 'out/x/lift_regs.bin', {mapBlocks});
//   ... m.run() ...   cap.tick(n) from the tick hook ...
//   cap.stop();

const fs = require('fs');
const M = require('./memory');

const CHUNK = 1 << 22;

class Capture {
  constructor(m, path, { mapBlocks } = {}) {
    this.m = m;
    this.fd = fs.openSync(path, 'w');
    this.buf = Buffer.alloc(CHUNK);
    this.n = 0;
    this.counts = { R: 0, W: 0, O: 0, T: 0 };
    this.isMapBlock = mapBlocks || null;   // Set of map block starts (all lifted blocks if null)
    this.put([0x50545352, 1, 0, 0]);
    this.prev = { instrument: m.instrument, onBlock: m.onBlock };
    m.enableInstrumentation({ coverage: false });
    m.onBlock = (mm, eip) => this.block(mm, eip);
    M.setWriteLog((size, addr, value) => this.write(size, addr, value));
    m.capture = this;
  }
  put(words) {
    if (this.n + 4 * words.length > CHUNK) this.flush();
    for (const w of words) { this.buf.writeUInt32LE(w >>> 0, this.n); this.n += 4; }
  }
  flush() { if (this.n) fs.writeSync(this.fd, this.buf, 0, this.n); this.n = 0; }
  block(m, eip) {
    if (this.isMapBlock !== null && !this.isMapBlock.has(eip)) return;
    this.counts.R++;
    this.put([0x52, eip, m.eax, m.ecx, m.edx, m.ebx, m.esp, m.ebp, m.esi, m.edi, m.getEflags()]);
  }
  write(size, addr, value) { this.counts.W++; this.put([0x57 | size << 8, addr, value]); }
  out(slot, ret) { this.counts.O++; this.put([0x4F, slot, ret]); }
  tick(n) { this.counts.T++; this.put([0x54, n]); }
  stop() {
    this.flush();
    fs.closeSync(this.fd);
    M.setWriteLog(null);
    this.m.capture = null;
    this.m.instrument = this.prev.instrument;
    this.m.onBlock = this.prev.onBlock;
    return this.counts;
  }
}

function start(m, path, opts) { return new Capture(m, path, opts); }

module.exports = { start, Capture };
