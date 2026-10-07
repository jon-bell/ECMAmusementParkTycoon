'use strict';
// DirectX: the oracle's fake DirectInput and failing DirectSound (pins, oracle/rcthook.c), and
// DirectDraw as Wine answers under Xvfb (one 32-bit display mode: the windowed GDI path).
const G = require('./guestmem');
const { HostNotImplemented } = require('./host');

const GUID_SysMouse = [0x6F1D2B60, 0x11CFD5A0, 0x4544C7BF, 0x00005453];

function install(H) {
  const W = H.W;
  // ---------------------------------------------------------------- DirectSound [pin]
  H.def('DSOUND.DLL!DirectSoundCreate', 3, (guid, pds, outer) => {
    H.log('DirectSoundCreate -> DSERR_NODRIVER');
    if (pds) G.w32(pds, 0);
    return W.DSERR_NODRIVER;
  });
  H.def('DSOUND.DLL!DirectSoundEnumerateA', 2, () => 0);

  // ---------------------------------------------------------------- DirectInput [pin]
  // rcthook.c: IDirectInputA and one IDirectInputDeviceA vtable shared by the keyboard and the
  // mouse; every method succeeds; GetDeviceState zero-fills and copies the script's key state.
  const devMethods = (kind) => [
    ['QueryInterface', 3, (t, r, o) => { G.w32(o, t); return 0; }], ['AddRef', 1, () => 1], ['Release', 1, () => 1],
    ['GetCapabilities', 2, () => 0], ['EnumObjects', 4, () => 0], ['GetProperty', 3, () => 0], ['SetProperty', 3, () => 0],
    ['Acquire', 1, () => 0], ['Unacquire', 1, () => 0],
    ['GetDeviceState', 3, (t, n, buf) => {
      G.fill(buf, n, 0);
      if (G.r32(t + 4) === 0) G.put(buf, H.input.keys.subarray(0, Math.min(n, 256)));
      if (G.r32(t + 4) === 1 && n >= 16) {   // DIMOUSESTATE: lX, lY, lZ, rgbButtons[4]
        const I = H.input;
        G.w32(buf, I.dmDx); G.w32(buf + 4, I.dmDy); I.dmDx = I.dmDy = 0;
        for (let i = 0; i < 4; i++) G.w8(buf + 12 + i, (I.dmButtons >> i) & 1 ? 0x80 : 0);
      }
      return 0;
    }],
    ['GetDeviceData', 5, (t, sz, buf, pn, fl) => { G.w32(pn, 0); return 0; }],
    ['SetDataFormat', 2, () => 0], ['SetEventNotification', 2, () => 0], ['SetCooperativeLevel', 3, () => 0],
    ['GetObjectInfo', 4, () => 0], ['GetDeviceInfo', 2, () => 0], ['RunControlPanel', 3, () => 0], ['Initialize', 4, () => 0],
  ];
  let devVtbl = 0;
  const mkdev = (kind) => {
    const o = devVtbl ? H.processHeap.alloc(8) : H.comObject('IDirectInputDeviceA', devMethods(), 4);
    if (!devVtbl) devVtbl = G.r32(o); else { G.w32(o, devVtbl); H.osObjects.push([o, 'IDirectInputDeviceA']); }
    G.w32(o + 4, kind);                 // fakedev_t {vtbl, kind}: 0 keyboard, 1 mouse
    return o;
  };
  let kbd = 0, mouse = 0, di = 0;
  H.def('DINPUT.DLL!DirectInputCreateA', 4, (hinst, ver, pout, outer) => {
    H.log(`DirectInputCreateA(0x${ver.toString(16)}) -> fake`);
    if (!di) {
      di = H.comObject('IDirectInputA', [
        ['QueryInterface', 3, (t, r, o) => { G.w32(o, t); return 0; }], ['AddRef', 1, () => 1], ['Release', 1, () => 1],
        ['CreateDevice', 4, (t, g, pdev, outer2) => {
          const isMouse = [0, 4, 8, 12].every((k, i) => G.r32(g + k) === GUID_SysMouse[i]);
          H.log(`DirectInput CreateDevice(${isMouse ? 'mouse' : 'keyboard'})`);
          if (isMouse) { if (!mouse) mouse = mkdev(1); G.w32(pdev, mouse); } else { if (!kbd) kbd = mkdev(0); G.w32(pdev, kbd); }
          return 0;
        }],
        ['EnumDevices', 5, () => 0], ['GetDeviceStatus', 2, () => 0], ['RunControlPanel', 3, () => 0], ['Initialize', 3, () => 0],
      ]);
    }
    G.w32(pout, di);
    return 0;
  });

  // ---------------------------------------------------------------- DirectDraw (Wine under Xvfb)
  const DD_METHODS = ['QueryInterface', 'AddRef', 'Release', 'Compact', 'CreateClipper', 'CreatePalette', 'CreateSurface',
    'DuplicateSurface', 'EnumDisplayModes', 'EnumSurfaces', 'FlipToGDISurface', 'GetCaps', 'GetDisplayMode', 'GetFourCCCodes',
    'GetGDISurface', 'GetMonitorFrequency', 'GetScanLine', 'GetVerticalBlankStatus', 'Initialize', 'RestoreDisplayMode',
    'SetCooperativeLevel', 'SetDisplayMode', 'WaitForVerticalBlank'];
  let dd = 0;
  function enumDisplayModes(t, flags, pdesc, ctx, cb) {
    if (flags || pdesc) throw new HostNotImplemented('IDirectDraw::EnumDisplayModes', `with flags ${flags} / a filter is not measured`);
    // Wine passes the DDSURFACEDESC in its own stack frame, 0x234 bytes below the caller's esp
    // [apitrace: EnumDisplayModes C esp 0x31FE2C, callback desc 0x31FBF8]
    const m = H.m, esp0 = m.esp;
    const p = (esp0 - 0x234) >>> 0;
    m.esp = (p - 0x10) >>> 0;
    try {
    for (const md of W.DISPLAY_MODES) {
      G.fill(p, 108, 0);
      G.w32(p, 108); G.w32(p + 4, md.flags); G.w32(p + 8, md.height); G.w32(p + 12, md.width); G.w32(p + 16, md.pitch);
      G.w32(p + 24, md.refresh);
      G.w32(p + 72, 32); G.w32(p + 76, md.pfFlags); G.w32(p + 84, md.bits);
      G.w32(p + 88, md.rmask); G.w32(p + 92, md.gmask); G.w32(p + 96, md.bmask); G.w32(p + 100, md.amask);
      if (!H.callback(cb, [p, ctx], 'enummodes')) break;
    }
    } finally { m.esp = esp0; }
    return 0;
  }
  H.ddrawProcs.DirectDrawCreate = H.hostFn('DDRAW.DLL!DirectDrawCreate', 3, (guid, pdd, outer) => {
    if (!dd) {
      dd = H.comObject('IDirectDraw', DD_METHODS.map((n) => {
        const nargs = { QueryInterface: 3, AddRef: 1, Release: 1, EnumDisplayModes: 5 }[n];
        if (n === 'EnumDisplayModes') return [n, 5, enumDisplayModes];
        if (n === 'AddRef' || n === 'Release') return [n, 1, () => 1];
        return [n, nargs || 1, () => { throw new HostNotImplemented(`IDirectDraw::${n}`); }];
      }));
    }
    G.w32(pdd, dd);
    return 0;
  });
  for (const n of ['DirectDrawEnumerateA', 'DirectDrawEnumerateW']) {
    H.ddrawProcs[n] = H.hostFn('DDRAW.DLL!' + n, 2, () => { throw new HostNotImplemented('DDRAW.DLL!' + n); });
  }
}
module.exports = { install };
