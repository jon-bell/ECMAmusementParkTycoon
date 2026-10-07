'use strict';
// GDI32: device contexts, the screen DIB section, palettes, fonts, regions. Nothing is drawn:
// the framebuffer is not part of the Stage 1 projections, and the game draws into its own 8-bit
// buffer (the DIB bits) that it then hands to StretchDIBits.
const G = require('./guestmem');

const DIB_BITS = 0x019A0000;   // where Wine put the DIB section's bits (docs/stage1-scope.md M6)

function install(H) {
  const W = H.W;
  const GW = W.GDI || {};
  const D = (n) => 'GDI32.DLL!' + n;
  const objs = new Map();      // handle -> {type, ...}
  let next = GW.FIRST_HANDLE || 0x01000100;
  const alloc = (type, o, h) => { if (h === undefined) { h = next; next += 4; } objs.set(h, { type, ...o }); return h; };

  // DCs. Wine's DCE cache hands a window the same cache DC each time it is released.
  const dcs = new Map();       // hwnd -> hdc
  const gdi = H.gdi = {
    objs,
    getDC(hwnd) {
      if (!dcs.has(hwnd)) dcs.set(hwnd, alloc('dc', { hwnd, palette: GW.DEFAULT_PALETTE || 0 }, (GW.DC || {})[hwnd] || (hwnd === 0 ? GW.SCREEN_DC : GW.WINDOW_DC)));
      return dcs.get(hwnd);
    },
    releaseDC(hwnd, hdc) { return objs.has(hdc) ? 1 : 0; },
    windowDC(hwnd) { return gdi.getDC(hwnd); },
    dialogFont(f) { return alloc('font', { face: f ? f.face : '', pt: f ? f.pt : 0 }, GW.DIALOG_FONT); },
    setRegion(h, rect) { const o = objs.get(h); if (o) o.rect = rect ? { ...rect } : null; },
    dib: null,
  };

  H.def(D('GetDeviceCaps'), 2, (hdc, i) => (W.DEVICE_CAPS[i] !== undefined ? W.DEVICE_CAPS[i] : 0));
  H.def(D('CreateCompatibleDC'), 1, (hdc) => alloc('memdc', { palette: GW.DEFAULT_PALETTE || 0 }, GW.COMPATIBLE_DC));
  H.def(D('DeleteDC'), 1, (hdc) => (objs.delete(hdc) ? 1 : 0));
  H.def(D('GdiFlush'), 0, () => 1);
  H.def(D('GetStockObject'), 1, (i) => ((GW.STOCK || {})[i] !== undefined ? GW.STOCK[i] : alloc('stock', { i })));
  H.def(D('GetSystemPaletteUse'), 1, () => W.SYSTEM_PALETTE_USE);
  H.def(D('CreateRectRgn'), 4, (l, t, r, b) => alloc('region', { rect: { l, t, r, b } }, GW.REGION));
  H.def(D('CreateFontIndirectA'), 1, (p) => alloc('font', { face: G.rstr(p + 28, 32), height: G.s32(p) }, GW.FONT));

  // The screen buffer: an 8-bit top-down DIB section; its bits live where Wine put them.
  H.def(D('CreateDIBSection'), 6, (hdc, bmi, usage, ppv, hsec, off) => {
    const w = G.s32(bmi + 4), h = G.s32(bmi + 8), bpp = G.r16(bmi + 14);
    const stride = ((w * bpp + 31) >>> 5) * 4;
    const size = stride * Math.abs(h);
    const base = gdi.dib ? 0 : DIB_BITS;
    if (!base) throw new Error('CreateDIBSection: a second DIB section is not implemented');
    if (H.space.reserve(size, base, 'dib') !== base) throw new Error('CreateDIBSection: cannot place the DIB bits');
    H.space.commit(base, size);
    const ncolors = bpp <= 8 ? (G.r32(bmi + 32) || 1 << bpp) : 0;
    const colors = G.bytes(bmi + G.r32(bmi), 4 * ncolors).slice();
    gdi.dib = { base, w, h, bpp, stride, colors };
    if (ppv) G.w32(ppv, base);
    H.log(`CreateDIBSection ${w}x${h}x${bpp} -> bits 0x${base.toString(16)}`);
    return alloc('bitmap', { dib: true }, GW.DIB_BITMAP);
  });
  H.def(D('StretchDIBits'), 13, (hdc, xd, yd, wd, hd, xs, ys, ws, hs, bits, bmi, usage, rop) => {
    if (H.onStretchDIBits) H.onStretchDIBits({ hdc, xd, yd, wd, hd, xs, ys, ws, hs, bits, bmi });
    // [apitrace] Wine returns the source DIB's height (|biHeight| = 768), not the copied lines
    return Math.abs(G.s32(bmi + 8));
  });

  // palettes
  H.def(D('CreatePalette'), 1, (p) => {
    const n = G.r16(p + 2);
    return alloc('palette', { entries: G.bytes(p + 4, 4 * n).slice() }, GW.PALETTE);
  });
  H.def(D('SelectPalette'), 3, (hdc, hpal, bg) => {
    const dc = objs.get(hdc);
    if (!dc || !objs.has(hpal) && hpal !== GW.DEFAULT_PALETTE) return 0;
    const old = dc.palette;
    dc.palette = hpal;
    return old;
  });
  H.def(D('RealizePalette'), 1, (hdc) => (GW.REALIZE_RESULT !== undefined ? GW.REALIZE_RESULT : 0));
  H.def(D('AnimatePalette'), 4, (hpal, start, n, pe) => {
    const o = objs.get(hpal);
    if (!o || o.type !== 'palette') return 0;
    for (let i = 0; i < n && start + i < o.entries.length / 4; i++) {
      const flags = o.entries[4 * (start + i) + 3];
      if (flags & 1) o.entries.set(G.bytes(pe + 4 * i, 4), 4 * (start + i));    // PC_RESERVED entries only
    }
    return 1;
  });
}

module.exports = { install, DIB_BITS };
