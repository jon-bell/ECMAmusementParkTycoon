'use strict';
// Smoke test of the runtime interface (lift/runtime/README.md) with hand-written blocks.
// Needs the user's rct.exe at game/cd/English/rct.exe (skipped otherwise).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const rt = require('../runtime');

const EXE = path.join(__dirname, '../../game/cd/English/rct.exe');
const have = fs.existsSync(EXE);

test('loader maps rct.exe and fills the IAT with host addresses', { skip: !have }, () => {
  const m = rt.createMachine({ exePath: EXE });
  assert.strictEqual(m.eip, 0x412E80);
  assert.strictEqual(m.imports.length, 207);
  for (const im of m.imports) {
    assert.strictEqual(rt.r32(im.iat), (rt.HOST_BASE + 16 * im.index) >>> 0);
    assert.strictEqual(im.addr, (rt.HOST_BASE + 16 * im.index) >>> 0);
  }
  assert.ok(m.importByKey.get('KERNEL32.DLL!GetVersion'));
  // code bytes are readable at their addresses: entry point starts with push ebp (0x55)
  assert.strictEqual(rt.r8(0x412E80), 0x55);
  // code is read-only to the guest, data is writable, null page faults
  assert.throws(() => rt.w8(0x412E80, 0), rt.GuestFault);
  assert.throws(() => rt.w32(0x9B3000, 0), /self-modifying/);
  assert.throws(() => rt.w8(0x5E7000, 0), /read-only/);
  rt.w32(0x5F4000, 0x12345678); assert.strictEqual(rt.r32(0x5F4000), 0x12345678);
  assert.throws(() => rt.r32(0), /null page/);
  assert.throws(() => rt.r32(rt.MEM_SIZE - 2), rt.GuestFault);
  assert.throws(() => rt.r8(0x01000000), /unmapped/);
  rt.mapPages(0x01000000, 0x2000, rt.PROT_RW);
  rt.w32(0x01000FFE, 0xA1B2C3D4); assert.strictEqual(rt.r32(0x01000FFE), 0xA1B2C3D4);   // crosses a page
  assert.throws(() => rt.w32(0x01001FFE, 0), /unmapped/);                                // runs off the mapping
  assert.throws(() => rt.r16(0x01001FFF), /unmapped/);
  // initial thread state
  assert.strictEqual(m.esp, rt.STACK_INIT - 4);
  assert.strictEqual(rt.r32(m.esp), rt.HOST_EXIT);
  assert.strictEqual(rt.r32(rt.TEB_BASE), 0xFFFFFFFF);
  assert.strictEqual(m.getEflags(), 0x202);
});

test('dispatch: blocks, host calls (stdcall/cdecl), callGuest nesting, hooks, exit', { skip: !have }, () => {
  const m = rt.createMachine({ exePath: EXE });
  const GV = m.importByKey.get('KERNEL32.DLL!GetVersion');
  const SM = m.importByKey.get('USER32.DLL!SendMessageA');
  const log = [];
  // Hand-written blocks standing in for lifted code.
  rt.installBlocks(m, {
    // entry: push 7; push 9; call [GetVersion IAT] ; (GetVersion is stdcall(0) here, test only)
    0x412E80: (m) => { m.push32(7); m.push32(9); m.push32(0x412E90); return rt.r32(GV.iat); },
    // after: call [SendMessageA] with 4 args -> host calls back into guest 0x413000
    0x412E90: (m) => { log.push(['after GetVersion', m.eax]); for (const v of [4, 3, 2, 1]) m.push32(v); m.push32(0x412EA0); return rt.r32(SM.iat); },
    0x412EA0: (m) => { log.push(['after SendMessage', m.eax, m.esp]); m.esp = (m.esp + 8) >>> 0; m.eax = 0x2A; return m.pop32(); /* ret -> HOST_EXIT */ },
    // the "window procedure": stdcall, 4 args; returns arg0+arg3 in eax, sets CF
    0x413000: (m) => { m.eax = (rt.r32(m.esp + 4) + rt.r32(m.esp + 16)) >>> 0; m.cf = 1; const r = m.pop32(); m.esp = (m.esp + 16) >>> 0; return r; },
  });
  m.bindImport('kernel32.dll!GetVersion', (m) => { m.eax = 0xC0000A04; m.retStd(0); });
  m.bindImport('USER32.dll!SendMessageA', (m) => {
    const a = [0, 1, 2, 3].map((i) => m.arg(i));
    for (const v of a.slice().reverse()) m.push32(v);
    const espBefore = m.esp + 16;
    const r = m.callGuest(0x413000, { ebx: 5 });
    assert.strictEqual(r.esp, espBefore);              // callee popped its args and HOST_RETURN
    assert.strictEqual(r.eflags & 1, 1);               // flags come back
    assert.strictEqual(m.eip, SM.addr);                // eip restored to the host address
    m.eax = r.eax; m.retStd(4);
  });
  let hookHits = 0;
  m.hooks.set(0x412E90, (mm) => { hookHits++; assert.strictEqual(mm.eip, 0x412E90); });
  assert.throws(() => m.hooks.set(0x412E91, () => {}), /not a forced block start/);
  const esp0 = m.esp;
  assert.throws(() => m.run(), (e) => e instanceof rt.GuestExit && e.code === 0x2A);
  assert.deepStrictEqual(log[0], ['after GetVersion', 0xC0000A04]);
  assert.strictEqual(log[1][1], 1 + 4);
  assert.strictEqual(log[1][2], esp0 - 8);
  assert.strictEqual(hookHits, 1);
});

test('hook redirect, specials, MissingBlock and HostMissing', { skip: !have }, () => {
  const m = rt.createMachine({ exePath: EXE });
  rt.installBlocks(m, {
    0x412E80: () => 0x412E90,
    0x412E90: () => 0x412EA0,
    0x412EA0: () => 0x00500001,     // not a block
  });
  m.hooks.set(0x412E90, () => 0x412EA0);   // skip 0x412E90's body
  assert.throws(() => m.run(), (e) => e instanceof rt.MissingBlock && e.eip === 0x500001 && /CODESEG/.test(e.message));
  // host address with no implementation
  const m2 = rt.createMachine({ exePath: EXE });
  rt.installBlocks(m2, { 0x412E80: () => m2.importByKey.get('KERNEL32.DLL!Sleep').addr });
  assert.throws(() => m2.run(), (e) => e instanceof rt.HostMissing && /KERNEL32.DLL!Sleep/.test(e.message));
  // specials and allocHost
  const m3 = rt.createMachine({ exePath: EXE });
  const h = m3.allocHost('IDirectDraw::Release', (mm) => { mm.eax = 0; mm.retStd(1); });
  assert.ok(h >= rt.HOST_BASE + 16 * 207);
  rt.installBlocks(m3, { 0x412E80: (mm) => { mm.push32(0); mm.push32(rt.HOST_RETURN_LOAD); return h; } });
  m3.specials.set(rt.HOST_RETURN_LOAD, (mm) => { mm.eax = 0x99; return rt.HOST_EXIT; });
  assert.throws(() => m3.run(), (e) => e instanceof rt.GuestExit && e.code === 0x99);
});

test('guest exceptions reach onException with the faulting state', { skip: !have }, () => {
  const m = rt.createMachine({ exePath: EXE });
  rt.installBlocks(m, {
    0x412E80: (mm) => { mm.eip = 0x412E85; throw new rt.GuestException('DE', 0x412E85); },
    0x412E90: (mm) => { mm.eax = 0x77; return rt.HOST_EXIT; },
  });
  m.onException = (mm, e) => { assert.strictEqual(e.kind, 'DE'); assert.strictEqual(mm.eip, 0x412E85); return 0x412E90; };
  assert.throws(() => m.run(), (e) => e instanceof rt.GuestExit && e.code === 0x77);
});

test('instrumented loop counts blocks and coverage', { skip: !have }, () => {
  const m = rt.createMachine({ exePath: EXE });
  rt.installBlocks(m, { 0x412E80: () => 0x412E90, 0x412E90: (mm) => { mm.eax = 1; return mm.pop32(); } });
  m.enableInstrumentation();
  const seen = [];
  m.onBlock = (mm, eip) => seen.push(eip);
  assert.throws(() => m.run(), rt.GuestExit);
  assert.deepStrictEqual(seen, [0x412E80, 0x412E90]);
  assert.strictEqual(m.blockCount, 2);
  assert.strictEqual(m.coverage[0x412E90 - rt.IMAGE_LO], 1);
});

test('register capture: R/W/O/T stream, started from a hook (loop switch)', { skip: !have }, () => {
  const capture = require('../runtime/capture');
  const os = require('os');
  const m = rt.createMachine({ exePath: EXE });
  const GV = m.importByKey.get('KERNEL32.DLL!GetVersion');
  let cap = null;
  rt.installBlocks(m, {
    0x412E80: (mm) => { mm.eax = 7; return 0x412E90; },
    0x412E90: (mm) => { rt.w32(0x5F4000, 0xAABBCCDD); rt.w8(0x5F4004, 0x11); return 0x412EA0; },
    0x412EA0: (mm) => { mm.push32(0x412EB0); mm.xslot = GV.iat; return rt.r32(GV.iat); },
    0x412EB0: (mm) => { cap.tick(5); return mm.pop32(); },
  });
  m.bindImport('KERNEL32.dll!GetVersion', (mm) => { mm.eax = 0x0A04; mm.retStd(0); });
  const file = path.join(os.tmpdir(), `lift-cap-${process.pid}.bin`);
  m.hooks.set(0x412E90, (mm) => { cap = capture.start(mm, file); });
  assert.throws(() => m.run(), rt.GuestExit);
  const counts = cap.stop();
  const b = fs.readFileSync(file); fs.unlinkSync(file);
  assert.deepStrictEqual(counts, { R: 3, W: 3, O: 1, T: 1 });   // W: 2 stores + the push of the return address
  assert.strictEqual(b.readUInt32LE(0), 0x50545352);
  assert.strictEqual(b.readUInt32LE(8), 0);                       // flags 0: lift stream
  // first record: R at 0x412E90 (the hooked block runs exactly once, inside the instrumented loop)
  assert.strictEqual(b.readUInt32LE(16), 0x52);
  assert.strictEqual(b.readUInt32LE(20), 0x412E90);
  assert.strictEqual(b.readUInt32LE(24), 7);
  assert.strictEqual(b.readUInt32LE(60), 0x457);                  // W: the 4-byte store
  assert.deepStrictEqual([b.readUInt32LE(64), b.readUInt32LE(68)], [0x5F4000, 0xAABBCCDD]);
  assert.strictEqual(b.readUInt32LE(72), 0x157);                  // W: the byte store
  // ... R 0x412EA0, W (push), O (slot = IAT of GetVersion, return address 0x412EB0), R 0x412EB0, T 5
  const o = b.indexOf(Buffer.from([0x4F, 0, 0, 0]), 84);
  assert.deepStrictEqual([b.readUInt32LE(o + 4), b.readUInt32LE(o + 8)], [GV.iat, 0x412EB0]);
  assert.deepStrictEqual([b.readUInt32LE(b.length - 8), b.readUInt32LE(b.length - 4)], [0x54, 5]);
});
