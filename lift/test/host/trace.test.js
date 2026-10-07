'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { TR, TraceWriter, readTrace, TRACE_VERSION } = require('../../host/trace');

test('record kinds are read from oracle/trace.h', () => {
  const h = fs.readFileSync(path.join(__dirname, '../../../oracle/trace.h'), 'utf8');
  const kinds = {};
  for (const m of h.matchAll(/TR_(\w+)\s*=\s*(0x[0-9A-Fa-f]+)/g)) kinds[m[1]] = parseInt(m[2], 16);
  assert.deepStrictEqual({ ...TR }, kinds);
  assert.strictEqual(TRACE_VERSION, Number(/TRACE_VERSION\s+(\d+)/.exec(h)[1]));
});

test('writer produces 16-byte little-endian records, across buffer flushes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tr-'));
  const p = path.join(dir, 'trace.bin');
  const w = new TraceWriter(p);
  const n = (1 << 18) + 7;           // more than one 4 MiB buffer
  for (let i = 0; i < n; i++) w.rec(TR.RNG, i, 0xFFFFFFFF, -1);
  w.close();
  assert.strictEqual(fs.statSync(p).size, 16 * n);
  const r = readTrace(p);
  assert.deepStrictEqual(r[0], [4, 0, 0xFFFFFFFF, 0xFFFFFFFF]);
  assert.deepStrictEqual(r[n - 1], [4, n - 1, 0xFFFFFFFF, 0xFFFFFFFF]);
  fs.rmSync(dir, { recursive: true });
});

test('pinned constants equal the oracle hook source (rcthook.c is the pin specification)', () => {
  const W = require('../../host/wine-answers');
  const c = fs.readFileSync(path.join(__dirname, '../../../oracle/rcthook.c'), 'utf8');
  const m = /#define ENV_BLOCK ([\s\S]*?)\n(?!\s)/.exec(c)[1];
  const lit = [...m.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]).join('').replace(/\\0/g, '\0').replace(/\\\\/g, '\\');
  assert.strictEqual(W.ENV_BLOCK, lit);
  assert.match(c, /strcpy\(b, "ORACLE"\); \*n = 6;/);
  assert.match(c, /strcpy\(b, "oracle"\); \*n = 7;/);
  assert.match(c, /\*spc = 8; \*bps = 512; \*freec = 0x40000; \*totc = 0x100000;/);
  assert.match(c, /#define VT_BASE\s+5000000u/);
  assert.match(c, /g_cur_x = 1000, g_cur_y = 740/);
});
