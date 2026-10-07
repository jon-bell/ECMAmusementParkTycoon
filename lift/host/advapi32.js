'use strict';
// ADVAPI32: the registry keys Setup.exe writes (install/rct1-install.reg; also in the oracle's
// prefix, game/prefix/system.reg) and the pinned user name.
const G = require('./guestmem');

const SETUP = 'SOFTWARE\\FISH TECHNOLOGY GROUP\\ROLLERCOASTER TYCOON SETUP';
// install/rct1-install.reg: [HKEY_LOCAL_MACHINE\Software\Fish Technology Group\RollerCoaster Tycoon Setup]
const REG = {
  'HKLM\\SOFTWARE\\FISH TECHNOLOGY GROUP': {},
  ['HKLM\\' + SETUP]: {
    CancelPrompt: { type: 1, s: 'Cancel' },
    CDKey: { type: 4, d: 0 },
    CharSet: { type: 4, d: 0 },
    Executable: { type: 1, s: 'rct.exe' },
    FontFaceName: { type: 1, s: 'MS Sans Serif' },
    FontPointSize: { type: 4, d: 12 },
    InstallLevel: { type: 4, d: 1 },
    Language: { type: 4, d: 0 },
    OKPrompt: { type: 1, s: 'OK' },
    Path: { type: 1, s: 'C:\\Program Files\\Hasbro Interactive\\RollerCoaster Tycoon' },
    SetupPath: { type: 1, s: 'D:\\' },
    Title: { type: 1, s: 'Rol' },
  },
};
const ROOTS = { 0x80000000: 'HKCR', 0x80000001: 'HKCU', 0x80000002: 'HKLM', 0x80000003: 'HKU' };

function install(H) {
  const A = (n) => 'ADVAPI32.DLL!' + n;
  const keys = new Map();
  const pathOf = (hk) => ROOTS[hk] || (keys.get(hk) || {}).path;
  H.def(A('RegOpenKeyA'), 3, (hk, psub, pres) => {
    const base = pathOf(hk);
    if (!base) return 6;                                      // ERROR_INVALID_HANDLE
    const sub = psub ? G.rstr(psub) : '';
    const p = sub ? base + '\\' + sub.toUpperCase().replace(/\\+$/, '') : base;
    H.log(`RegOpenKeyA(${p})`);
    if (!REG[p] && !ROOTS[hk]) return 2;
    if (!REG[p] && sub) return 2;                             // ERROR_FILE_NOT_FOUND
    const h = H.handles.alloc({ type: 'key', path: p });
    keys.set(h, { path: p });
    G.w32(pres, h);
    return 0;
  });
  H.def(A('RegCloseKey'), 1, (hk) => { if (!keys.has(hk)) return 6; keys.delete(hk); H.handles.free(hk); return 0; });
  H.def(A('RegQueryValueExA'), 6, (hk, pname, res, ptype, pdata, plen) => {
    const k = REG[pathOf(hk)];
    if (!k) return 6;
    const name = pname ? G.rstr(pname) : '';
    const v = Object.entries(k).find(([n]) => n.toUpperCase() === name.toUpperCase());
    H.log(`RegQueryValueExA(${pathOf(hk)}, ${name}) -> ${v ? JSON.stringify(v[1]) : 'not found'}`);
    if (!v) return 2;
    const val = v[1];
    const bytes = val.type === 4 ? Uint8Array.of(val.d & 255, val.d >>> 8 & 255, val.d >>> 16 & 255, val.d >>> 24) : Buffer.from(val.s + '\0', 'latin1');
    if (ptype) G.w32(ptype, val.type);
    if (!plen) return pdata ? 87 : 0;
    const have = G.r32(plen);
    G.w32(plen, bytes.length);
    if (!pdata) return 0;
    if (have < bytes.length) return 234;                     // ERROR_MORE_DATA
    G.put(pdata, bytes);
    return 0;
  });
  H.def(A('GetUserNameA'), 2, (buf, pn) => {                  // [pin] rcthook.c: "oracle", *n = 7
    G.wstr(buf, H.W.USER_NAME); G.w32(pn, H.W.USER_NAME.length + 1); return 1;
  });
}
module.exports = { install, REG };
