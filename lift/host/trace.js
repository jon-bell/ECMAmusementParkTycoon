'use strict';
// Trace writer in the oracle's format (oracle/trace.h): 16-byte records {kind, a, b, c}, four
// little-endian uint32. Record kinds come from oracle/trace.h (below).
const fs = require('fs');
const os = require('os');

// Record kinds and the version come from oracle/trace.h itself (the format's definition), so new
// kinds the oracle adds are picked up without a second copy to keep in sync.
const path = require('path');
const TRACE_H = path.join(__dirname, '../../oracle/trace.h');
const traceH = fs.readFileSync(TRACE_H, 'utf8');
const TRACE_VERSION = Number(/#define\s+TRACE_VERSION\s+(\d+)/.exec(traceH)[1]);
const TR = Object.freeze(Object.fromEntries([...traceH.matchAll(/TR_(\w+)\s*=\s*(0x[0-9A-Fa-f]+)/g)].map((x) => [x[1], parseInt(x[2], 16)])));
for (const k of ['HEADER', 'FRAME', 'TICK', 'RNG', 'CHUNK', 'STATE', 'COMMAND', 'REGS_IN', 'REGS_IN2', 'INJECT', 'REGS_OUT',
  'REGS_OUT2', 'REGS_OUT3', 'INPUT', 'LOAD', 'MSG', 'MSG_DROP', 'FILE', 'NOTE', 'FINAL', 'END', 'INJ_IN', 'INJ_IN2', 'MSTATE']) {
  if (TR[k] === undefined) throw new Error(`oracle/trace.h lacks TR_${k}`);
}

if (os.endianness() !== 'LE') throw new Error('trace writer assumes a little-endian host');

// rcthook.c buffers 4 MiB and writes when full, at quit, and (on process detach) at the end.
// Buffering is invisible in the file; this writer flushes at the same size for simplicity.
const TBUF_WORDS = (1 << 22) / 4;

class TraceWriter {
  /** @param {string|null} path  trace.bin to create (null: in-memory only, for tests) */
  constructor(path) {
    this.path = path;
    this.fd = path ? fs.openSync(path, 'w') : -1;
    this.buf = new Uint32Array(TBUF_WORDS);
    this.n = 0;               // words used in buf
    this.count = 0;           // records written in total
    this.mem = path ? null : [];  // in-memory copy when no file
    this.closed = false;
  }
  rec(kind, a, b, c) {
    if (this.closed) return;
    if (this.n + 4 > this.buf.length) this.flush();
    const p = this.buf, n = this.n;
    p[n] = kind; p[n + 1] = a; p[n + 2] = b; p[n + 3] = c;   // ToUint32 on store
    this.n = n + 4;
    this.count++;
  }
  flush() {
    if (this.n === 0) return;
    if (this.fd >= 0) {
      fs.writeSync(this.fd, Buffer.from(this.buf.buffer, 0, this.n * 4));
    } else {
      for (let i = 0; i < this.n; i += 4) this.mem.push([this.buf[i], this.buf[i + 1], this.buf[i + 2], this.buf[i + 3]]);
    }
    this.n = 0;
  }
  close() {
    if (this.closed) return;
    this.flush();
    if (this.fd >= 0) fs.closeSync(this.fd);
    this.fd = -1;
    this.closed = true;
  }
  /** records as [kind,a,b,c] arrays (in-memory writers only) */
  records() { this.flush(); return this.mem; }
}

/** Read a trace file into [[kind,a,b,c], ...] (tests and debugging only; never used by a run). */
function readTrace(path) {
  const b = fs.readFileSync(path);
  const n = Math.floor(b.length / 16), out = new Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = [b.readUInt32LE(16 * i), b.readUInt32LE(16 * i + 4), b.readUInt32LE(16 * i + 8), b.readUInt32LE(16 * i + 12)];
  }
  return out;
}

module.exports = { TR, TRACE_VERSION, TraceWriter, readTrace };
