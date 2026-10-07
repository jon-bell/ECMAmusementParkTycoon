#!/usr/bin/env node
'use strict';
// Microbenchmark: lifted rct.exe code via callGuest, no host needed.
//   /usr/bin/nodejs lift/test/bench.js [liftDir]
// Workload: the startup tamper checksum (0x5DF3C0..0x5DF40B: XOR-rotate over 0x42EAE0-0x431510,
// ~54k instructions, 2 loops of 5 instructions), run repeatedly.
const path = require('path');
const rt = require('../runtime');
const ROOT = path.join(__dirname, '../..');
const m = rt.createMachine({ exePath: path.join(ROOT, 'game/cd/English/rct.exe'), liftDir: process.argv[2] || path.join(ROOT, 'out/lift') });
function once() { m.esp = 0x0032F000; return m.callGuest(0x5DF3C0, {}); }
m.enableInstrumentation({ coverage: false });
once();
const perCall = m.insnCount, blocksPerCall = m.blockCount;
const sum = rt.r32(0x6E2B76);
m.instrument = false;
for (let k = 0; k < 200; k++) once();      // warm up
const N = 3000;
const t0 = process.hrtime.bigint();
for (let k = 0; k < N; k++) once();
const s = Number(process.hrtime.bigint() - t0) / 1e9;
console.log(JSON.stringify({ checksum: '0x' + sum.toString(16), insns_per_call: perCall, blocks_per_call: blocksPerCall,
  minsns_per_s: +(perCall * N / s / 1e6).toFixed(1), mblocks_per_s: +(blocksPerCall * N / s / 1e6).toFixed(1) }));
