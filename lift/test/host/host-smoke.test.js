'use strict';
// Host functions called through the runtime's host-call ABI (no lifted code needed): pins,
// files through the overlay, find with CD aliases, registry, the fake DirectInput, DirectDraw.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const rt = require('../../runtime');
const { attach } = require('../../host');
const { readTrace, TR, TRACE_VERSION } = require('../../host/trace');

const ROOT = path.resolve(__dirname, '../../..');
const EXE = path.join(ROOT, 'game/cd/English/rct.exe');
const have = fs.existsSync(EXE);

function setup(script = 'seed 7000000\nframe 5 quit\n') {
  const m = rt.createMachine({ exePath: EXE });
  // only host code runs here: stand-in blocks at the hook addresses (never executed)
  rt.installBlocks(m, Object.fromEntries([0x5DF42A, 0x43888E, 0x4385D8, 0x4386EC, 0x426F56, 0x43054E].map((a) => [a, () => { throw new Error('not lifted'); }])));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'hostsmoke-'));
  const h = attach(m, { rt, outDir: out, scriptText: script });
  // scratch guest memory for arguments
  const scratch = h.processHeap.alloc(0x10000);
  const call = (key, ...args) => {
    const im = m.importByKey.get(key);
    for (let i = args.length - 1; i >= 0; i--) m.push32(args[i] >>> 0);
    return m.callGuest(im ? im.addr : key).eax;   // callGuest pushes the return address
  };
  const callAddr = (addr, ...args) => { for (let i = args.length - 1; i >= 0; i--) m.push32(args[i] >>> 0); return m.callGuest(addr).eax; };
  const str = (a, s) => { rt.writeCString(a, s); return a; };
  return { m, h, out, scratch, call, callAddr, str };
}

test('pins: virtual clock, system time, machine identity', { skip: !have && 'no rct.exe' }, () => {
  const { h, call, scratch, out } = setup();
  assert.strictEqual(call('WINMM.DLL!timeGetTime'), 7000000);
  assert.strictEqual(call('WINMM.DLL!timeGetTime'), 7000001);
  call('KERNEL32.DLL!GetSystemTime', scratch);
  const w = (i) => rt.dv.getUint16(scratch + 2 * i, true);
  assert.deepStrictEqual([0, 1, 2, 3, 4, 5, 6, 7].map(w), [2000, 1, 4, 13, 12, 33, 20, 2]);
  assert.strictEqual(call('KERNEL32.DLL!GetComputerNameA', scratch, scratch + 64), 1);
  assert.strictEqual(rt.readCString(scratch), 'ORACLE');
  assert.strictEqual(call('USER32.DLL!GetCursorPos', scratch), 1);
  assert.deepStrictEqual([rt.dv.getUint32(scratch, true), rt.dv.getUint32(scratch + 4, true)], [1000, 740]);
  assert.strictEqual(call('DSOUND.DLL!DirectSoundCreate', 0, scratch, 0), 0x88780078);
  assert.strictEqual(call('KERNEL32.DLL!GetVersion'), 0x23F00206);
  h.finish({ exit: 0 });
  const recs = readTrace(path.join(out, 'trace.bin'));
  assert.deepStrictEqual(recs[0], [TR.HEADER, TRACE_VERSION, 0, 1]);
  assert.deepStrictEqual([recs[1][0], recs[1][3]], [TR.BUILD, 1]);   // build id, producer 1 (lift host)
  assert.deepStrictEqual(recs[2], [TR.NOTE, 0, 0, 7000000]);
});

test('files: overlay writes, case-insensitive reads, find with the CD alias', { skip: !have && 'no rct.exe' }, () => {
  const { h, call, scratch, str, out } = setup();
  const GD = 'C:\\Program Files\\Hasbro Interactive\\RollerCoaster Tycoon';
  const f = call('KERNEL32.DLL!CreateFileA', str(scratch, GD + '\\Data\\GAME.CFG'), 0x80000000, 1, 0, 3, 0x80, 0);
  assert.notStrictEqual(f, 0xFFFFFFFF);
  assert.strictEqual(call('KERNEL32.DLL!ReadFile', f, scratch + 0x1000, 100, scratch + 0x800, 0), 1);
  const n = rt.dv.getUint32(scratch + 0x800, true);
  assert.ok(n > 0 && n <= 100);
  assert.strictEqual(call('KERNEL32.DLL!CloseHandle', f), 1);
  const g = call('KERNEL32.DLL!CreateFileA', str(scratch, GD + '\\Scenarios\\SC.IDX'), 0x40000000, 0, 0, 2, 0x80, 0);
  // Wine's handle numbering (wine-answers.js HANDLES): the first handle is 0xC8, which Wine
  // takes again after it is closed; then the lowest free value
  assert.deepStrictEqual([f, g], [0xC8, 0xCC]);
  str(scratch + 0x100, 'hello');
  assert.strictEqual(call('KERNEL32.DLL!WriteFile', g, scratch + 0x100, 5, scratch + 0x800, 0), 1);
  call('KERNEL32.DLL!CloseHandle', g);
  assert.strictEqual(fs.readFileSync(path.join(out, 'overlay/Scenarios/SC.IDX'), 'latin1'), 'hello');
  const fh = call('KERNEL32.DLL!FindFirstFileA', str(scratch, 'D:\\Saved Games'), scratch + 0x1000);
  assert.notStrictEqual(fh, 0xFFFFFFFF);
  assert.strictEqual(rt.readCString(scratch + 0x1000 + 44), 'Saved Games');
  assert.strictEqual(rt.readCString(scratch + 0x1000 + 304), 'SAVED~1');
  assert.strictEqual(fh, 0x46490000, 'pinned search handle (slot 0)');
  assert.strictEqual(call('KERNEL32.DLL!FindClose', fh), 1);
  const sh = call('KERNEL32.DLL!FindFirstFileA', str(scratch, GD + '\\Scenarios\\*.SC4'), scratch + 0x1000);
  const names = [rt.readCString(scratch + 0x1000 + 44)];
  while (call('KERNEL32.DLL!FindNextFileA', sh, scratch + 0x1000)) names.push(rt.readCString(scratch + 0x1000 + 44));
  assert.deepStrictEqual(names, [...names].sort());
  assert.strictEqual(names[0], 'SC10.SC4');
  assert.ok(names.includes('sc6.sc4'));
  h.finish({ exit: 0 });
  const recs = readTrace(path.join(out, 'trace.bin')).filter((r) => r[0] === TR.FILE);
  assert.strictEqual(recs.length, 2);
});

test('registry, DirectInput fake, DirectDraw display modes', { skip: !have && 'no rct.exe' }, () => {
  const { h, m, call, callAddr, scratch, str } = setup();
  assert.strictEqual(call('ADVAPI32.DLL!RegOpenKeyA', 0x80000002, str(scratch, 'Software\\Fish Technology Group\\RollerCoaster Tycoon Setup'), scratch + 0x100), 0);
  const hk = rt.dv.getUint32(scratch + 0x100, true);
  rt.dv.setUint32(scratch + 0x200, 260, true);
  assert.strictEqual(call('ADVAPI32.DLL!RegQueryValueExA', hk, str(scratch + 0x300, 'Path'), 0, scratch + 0x204, scratch + 0x400, scratch + 0x200), 0);
  assert.strictEqual(rt.readCString(scratch + 0x400), 'C:\\Program Files\\Hasbro Interactive\\RollerCoaster Tycoon');
  // DirectInput: CreateDevice(mouse GUID), GetDeviceState
  assert.strictEqual(call('DINPUT.DLL!DirectInputCreateA', 0x400000, 0x500, scratch, 0), 0);
  const di = rt.dv.getUint32(scratch, true), vt = rt.dv.getUint32(di, true);
  const kbdGuid = scratch + 0x500;
  rt.writeBytes(kbdGuid, new Uint8Array(16));
  assert.strictEqual(callAddr(rt.dv.getUint32(vt + 12, true), di, kbdGuid, scratch + 4, 0), 0);
  const kbd = rt.dv.getUint32(scratch + 4, true);
  h.input.keys[30] = 0x80;
  const dvt = rt.dv.getUint32(kbd, true);
  assert.strictEqual(callAddr(rt.dv.getUint32(dvt + 36, true), kbd, 256, scratch + 0x600), 0);
  assert.strictEqual(rt.mem[scratch + 0x600 + 30], 0x80);
  // DirectDraw via LoadLibraryA/GetProcAddress, EnumDisplayModes counting callback (guest code
  // replaced by a host function here)
  const mod = call('KERNEL32.DLL!LoadLibraryA', str(scratch, 'DDRAW.DLL'));
  const create = call('KERNEL32.DLL!GetProcAddress', mod, str(scratch + 0x20, 'DirectDrawCreate'));
  assert.ok(create);
  assert.strictEqual(callAddr(create, 0, scratch + 0x40, 0), 0);
  const dd = rt.dv.getUint32(scratch + 0x40, true);
  let modes = [];
  const cb = h.hostFn('test-cb', 2, (desc, ctx) => { modes.push([rt.dv.getUint32(desc + 12, true), rt.dv.getUint32(desc + 8, true), rt.dv.getUint32(desc + 84, true)]); return 1; });
  assert.strictEqual(callAddr(rt.dv.getUint32(rt.dv.getUint32(dd, true) + 32, true), dd, 0, 0, 0, cb), 0);
  assert.deepStrictEqual(modes, [[1024, 768, 32]]);
  h.finish({ exit: 0 });
});

test('never-called imports throw naming the function', { skip: !have && 'no rct.exe' }, () => {
  const { h, call } = setup();
  assert.throws(() => call('SHELL32.DLL!DragAcceptFiles', 0, 0), /DragAcceptFiles/);
  h.finish({ exit: 0 });
});
