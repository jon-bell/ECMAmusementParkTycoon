'use strict';
// The modeless start-up dialog: CreateDialogParamA(hInst, #101, main window, 0x4037CF, 0), as
// Wine 9 builds it (user32 dialog.c DIALOG_CreateIndirect + win32u activation/focus):
//   1. the dialog window (class #32770) is created hidden; its own creation messages go to the
//      default dialog procedure before the game's dialog procedure is attached (invisible);
//   2. WM_SETFONT (template font) to the dialog (game dialog procedure first, as DefDlgProc does
//      for every message);
//   3. the controls in template order, each followed by WM_SETFONT; the edit control sets its
//      IME composition font when created and on every WM_SETFONT, and Wine's IME notifies the
//      window owning the input context (the focus window, i.e. the game's main window) with
//      WM_IME_NOTIFY(IMN_SETCOMPOSITIONFONT): the three 0x282 messages in hook.log;
//   4. WM_INITDIALOG(first tab-stop control); the game's handler returns 0 (no default focus);
//   5. ShowWindow(SW_SHOWNORMAL) because the template has WS_VISIBLE.
const G = require('./guestmem');

function install(H, U) {
  const { wins, state, newWindow, send, setFocus, WM } = U;
  const UW = H.W.USER || {};
  const m = H.m;

  // ---------------------------------------------------------------- resources (from the image)
  function findResource(type, id) {
    const base = 0x400000;
    const pe = base + G.r32(base + 0x3C);
    const dir = base + G.r32(pe + 24 + 96 + 16);
    const entry = (d, want) => {
      const nNamed = G.r16(d + 12), nId = G.r16(d + 14);
      for (let i = 0; i < nNamed + nId; i++) {
        const e = d + 16 + 8 * i;
        const name = G.r32(e), off = G.r32(e + 4);
        if (want === null || (!(name & 0x80000000) && name === want)) return off;
      }
      return null;
    };
    let o = entry(dir, type); if (o === null) return null;
    o = entry(dir + (o & 0x7FFFFFFF), id); if (o === null) return null;
    o = entry(dir + (o & 0x7FFFFFFF), null); if (o === null) return null;
    const data = dir + o;
    return { addr: base + G.r32(data), size: G.r32(data + 4) };
  }

  /** DLGTEMPLATE (not EX) parser. */
  function parseTemplate(p) {
    const style = G.r32(p), ex = G.r32(p + 4), n = G.r16(p + 8);
    const xy = [10, 12, 14, 16].map((o) => (G.r16(p + o) << 16) >> 16);
    let o = p + 18;
    const sz = () => {
      const w = G.r16(o);
      if (w === 0xFFFF) { const v = G.r16(o + 2); o += 4; return '#' + v; }
      let s = '';
      for (;;) { const c = G.r16(o); o += 2; if (!c) break; s += String.fromCharCode(c); }
      return s;
    };
    const menu = sz(), cls = sz(), title = sz();
    let font = null;
    if (style & 0x40) { const pt = G.r16(o); o += 2; font = { pt, face: sz() }; }
    const ctls = [];
    for (let i = 0; i < n; i++) {
      o = (o + 3) & ~3;
      const c = { style: G.r32(o), ex: G.r32(o + 4), x: (G.r16(o + 8) << 16) >> 16, y: (G.r16(o + 10) << 16) >> 16,
        cx: (G.r16(o + 12) << 16) >> 16, cy: (G.r16(o + 14) << 16) >> 16, id: G.r16(o + 16) };
      o += 18;
      c.cls = sz(); c.text = sz();
      const extra = G.r16(o); o += 2 + extra;
      ctls.push(c);
    }
    return { style, ex, xy, menu, cls, title, font, ctls };
  }

  // ---------------------------------------------------------------- built-in control classes
  const sys = (name) => {
    const k = name.toUpperCase();
    if (!U.classes.has(k)) U.classes.set(k, { name, proc: 0, cursor: 0, filtered: false, system: true });
    return U.classes.get(k);
  };
  const CTL_CLASS = { '#128': 'Button', '#129': 'Edit', '#130': 'Static' };

  /** Host window procedure of a control (no game code behind it). */
  function controlProc(kind) {
    return (hwnd, msg, wp, lp) => {
      const w = wins.get(hwnd);
      switch (msg) {
        case WM.SETTEXT: w.text = lp ? G.rstr(lp) : ''; return 1;
        case WM.SETFONT:
          w.font = wp;
          if (kind === 'Edit') imeCompositionFont();
          return 0;
        case WM.GETFONT: return w.font;
        // an edit control tells its parent when it gains or loses the focus (EN_SETFOCUS, EN_KILLFOCUS)
        case WM.SETFOCUS: if (kind === 'Edit') send(w.parent, WM.COMMAND, (w.id | 0x100 << 16) >>> 0, hwnd); return 0;
        case WM.KILLFOCUS: if (kind === 'Edit') send(w.parent, WM.COMMAND, (w.id | 0x200 << 16) >>> 0, hwnd); return 0;
        case 0x87: return kind === 'Edit' ? 0x89 : kind === 'Button' ? ((w.style & 0xF) === 1 ? 0x2010 : 0x2000) : 0x100; // WM_GETDLGCODE
        case 0xB1: return 1;      // EM_SETSEL
        default: return 0;
      }
    };
  }
  /** Wine imm32 ImmSetCompositionFont: WM_IME_NOTIFY(IMN_SETCOMPOSITIONFONT) to the IMC's window. */
  function imeCompositionFont() {
    const target = state.imeWindow !== undefined ? state.imeWindow : state.focus;
    if (target) send(target, WM.IME_NOTIFY, 0xA, 0);
  }

  // ---------------------------------------------------------------- DefDlgProc
  function defDlgProc(hwnd, msg, wp, lp) {
    const d = wins.get(hwnd);
    if (d.dlgProc) {
      const r = H.callback(d.dlgProc, [hwnd, msg, wp, lp], 'dlgproc');
      if (r) {
        // DefDlgProc returns the dialog procedure's result for these, DWLP_MSGRESULT otherwise
        if ([WM.INITDIALOG, 0x135, 0x133, 0x134, 0x138, 0x136, 0x137, 0x2B, 0x87, 0x4E, 0x84, 0x55, 0x2C, 0x39, 0x34].includes(msg)) return r;
        return d.msgResult || 0;
      }
    }
    if (d.destroyed && msg !== WM.NCDESTROY) return 0;
    switch (msg) {
      case WM.SETFONT: d.font = wp; return 0;
      case WM.GETFONT: return d.font;
      case WM.ACTIVATE:
        if (wp & 0xFFFF) restoreFocus(d, true); else if (state.focus && U.wins.get(state.focus) && U.wins.get(state.focus).parent === hwnd) d.savedFocus = state.focus;
        return 0;
      case WM.SETFOCUS: restoreFocus(d, false); return 0;
      case WM.CLOSE: send(hwnd, WM.COMMAND, 2, d.ctlByHwnd ? 0 : 0); return 0;
      // DEFDLG_Proc: the background brush comes from WM_CTLCOLORDLG sent to the dialog itself
      case WM.ERASEBKGND: send(hwnd, 0x136, wp, hwnd); return 1;
      default: return U.defWindowProc(hwnd, msg, wp, lp);
    }
  }
  function restoreFocus(d, justActivate) {
    if (!d.savedFocus || !wins.has(d.savedFocus) || d.savedFocus === d.hwnd) {
      if (justActivate) return;
      d.savedFocus = d.tabFirst;
      if (!d.savedFocus) return;
    }
    setFocus(d.savedFocus);
    d.savedFocus = 0;
  }

  // ---------------------------------------------------------------- CreateDialogParamA
  H.def('USER32.DLL!CreateDialogParamA', 5, (hinst, tmpl, owner, proc, param) => {
    if (tmpl >>> 16) throw new Error('CreateDialogParamA by name is not implemented');
    const res = findResource(5, tmpl);
    if (!res) { H.lastError = 1814; return 0; }
    const t = parseTemplate(res.addr);
    const dlgClass = sys('#32770');
    const R = UW.DIALOG_RECT;   // [apitrace] where Wine placed the dialog (dialog units -> pixels)
    const d = newWindow({ hwnd: UW.DIALOG_HWND, cls: dlgClass, proc: defDlgProc, style: t.style & ~0x10000000, exStyle: t.ex | 0x10000,
      x: R[0], y: R[1], w: R[2], h: R[3], text: t.title, parent: 0 });
    d.owner = owner;
    d.isDialog = true;
    d.dlgProc = proc;
    d.font = H.gdi ? H.gdi.dialogFont(t.font) : 0;
    send(d.hwnd, WM.SETFONT, d.font, 0);
    const ids = UW.DIALOG_CONTROLS || {};
    d.tabFirst = 0;
    for (const c of t.ctls) {
      const cname = CTL_CLASS[c.cls] || c.cls;
      const cw = newWindow({ hwnd: ids[c.id], cls: sys(cname), proc: controlProc(cname), style: c.style, exStyle: c.ex | 0x4,
        x: c.x, y: c.y, w: c.cx, h: c.cy, text: c.text, parent: d.hwnd, id: c.id });
      if (cname === 'Edit') imeCompositionFont();          // EDIT_WM_Create sets the default font
      send(cw.hwnd, WM.SETFONT, d.font, 0);
      if (!d.tabFirst && (c.style & 0x10010000) === 0x10010000) d.tabFirst = cw.hwnd;   // WS_VISIBLE|WS_TABSTOP
    }
    H.log(`CreateDialogParamA(#${tmpl}) -> ${d.hwnd.toString(16)} controls ${d.children.map((h) => h.toString(16)).join(',')}`);
    const r = send(d.hwnd, WM.INITDIALOG, d.tabFirst, param);
    if (r && wins.has(d.hwnd) && !d.destroyed && d.tabFirst) setFocus(d.tabFirst);
    if (!d.destroyed && (t.style & 0x10000000)) U.showWindow(d);
    return d.hwnd;
  });

  const child = (hdlg, id) => {
    const d = wins.get(hdlg);
    if (!d) return null;
    for (const h of d.children) { const c = wins.get(h); if (c && c.id === id && !c.destroyed) return c; }
    return null;
  };
  H.def('USER32.DLL!GetDlgItem', 2, (hdlg, id) => { const c = child(hdlg, id); if (!c) { H.lastError = 1421; return 0; } return c.hwnd; });
  H.def('USER32.DLL!SetDlgItemTextA', 3, (hdlg, id, p) => { const c = child(hdlg, id); if (!c) return 0; return send(c.hwnd, WM.SETTEXT, 0, p) ? 1 : 0; });
  H.def('USER32.DLL!SendDlgItemMessageA', 5, (hdlg, id, msg, wp, lp) => { const c = child(hdlg, id); if (!c) return 0; return send(c.hwnd, msg, wp, lp); });
  H.def('USER32.DLL!SetWindowTextA', 2, (h, p) => (send(h, WM.SETTEXT, 0, p) ? 1 : 0));
}

module.exports = { install };
