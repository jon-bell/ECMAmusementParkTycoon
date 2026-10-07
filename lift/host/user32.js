'use strict';
// USER32: window classes, windows, the message queue, the oracle's window-procedure filter,
// the start-up dialog #101, DCs, cursors, metrics.
//
// Window messages are part of what the game observes (its window procedure 0x403D79 and dialog
// procedure 0x4037CF change .data state) and part of the trace (TR_MSG, TR_MSG_DROP, projection
// `os`). The sequences below reproduce what Wine 9.0 sends in the oracle's environment (no window
// manager, Xvfb 1024x768x24). Evidence: the oracle's hook.log 'msg' lines and TR_MSG records
// (every corpus case shows the same 35 messages and 2 dropped ones), and the API trace.
const G = require('./guestmem');
const { TR } = require('./trace');

const WM = {
  CREATE: 0x1, DESTROY: 0x2, MOVE: 0x3, SIZE: 0x5, ACTIVATE: 0x6, SETFOCUS: 0x7, KILLFOCUS: 0x8,
  SETTEXT: 0xC, PAINT: 0xF, CLOSE: 0x10, ERASEBKGND: 0x14, SHOWWINDOW: 0x18, ACTIVATEAPP: 0x1C,
  SETCURSOR: 0x20, GETMINMAXINFO: 0x24, WINDOWPOSCHANGING: 0x46, WINDOWPOSCHANGED: 0x47,
  GETICON: 0x7F, NCCREATE: 0x81, NCDESTROY: 0x82, NCCALCSIZE: 0x83, NCHITTEST: 0x84, NCPAINT: 0x85,
  NCACTIVATE: 0x86, INITDIALOG: 0x110, COMMAND: 0x111, TIMER: 0x113, MOUSEMOVE: 0x200,
  IME_SETCONTEXT: 0x281, IME_NOTIFY: 0x282, QUERYNEWPALETTE: 0x30F, PALETTEISCHANGING: 0x310,
  SETFONT: 0x30, GETFONT: 0x31, PARENTNOTIFY: 0x210,
};
const MSGNAME = Object.fromEntries(Object.entries(WM).map(([k, v]) => [v, k]));

/** rcthook.c is_input_msg(): user input the oracle drops before the game's window procedure. */
function isInputMsg(m) {
  return (m >= 0x200 && m <= 0x20E) || (m >= 0x100 && m <= 0x109) || (m >= 0xA0 && m <= 0xAD) ||
    m === 0x2A1 || m === 0x2A3 || m === 0x2A0 || m === 0x2A2 || m === 0x20 || m === 0x215 || m === 0xFF;
}

function install(H) {
  const W = H.W;
  const U = (n) => 'USER32.DLL!' + n;
  const hx = (v) => '0x' + (v >>> 0).toString(16);
  const m = H.m;
  const UW = W.USER || {};

  let pointerPending = false, paintSeen = false;
  // messages the script posts (char, move): rcthook.c PostMessageA to the main window, and the
  // filter's FIFO of them, which it lets through to the game's window procedure
  const scriptq = [];
  H.postScriptMessage = (q) => {
    if (!state.mainHwnd || scriptq.length >= 64) return false;
    scriptq.push(q);
    state.queue.push({ hwnd: state.mainHwnd, message: q.m, wParam: q.w, lParam: q.l });
    return true;
  };

  // ---------------------------------------------------------------- user handles
  // Wine numbers user objects (windows, cursors, icons) from one table: low word 0x20 + 2*index,
  // high word a generation counter. The values the game sees are documented constants
  // (wine-answers.js USER); the allocator below continues from the last documented value.
  let nextUser = UW.FIRST_HANDLE || 0x10020;
  const userHandle = () => { const h = nextUser; nextUser += 2; return h; };

  // ---------------------------------------------------------------- classes and windows
  const classes = new Map();      // upper-case name -> class
  const wins = new Map();         // hwnd -> window
  let atomNext = UW.FIRST_ATOM || 0xC000;
  const state = H.user = { classes, wins, focus: 0, active: 0, mainHwnd: 0, capture: 0, cursor: 0, queue: [], pending: [] };

  H.def(U('RegisterClassA'), 1, (p) => {
    const namep = G.r32(p + 36);
    const name = namep >>> 16 ? G.rstr(namep) : '#' + namep;
    const c = { name, style: G.r32(p), proc: G.r32(p + 4), clsExtra: G.r32(p + 8), wndExtra: G.r32(p + 12),
      hinst: G.r32(p + 16), icon: G.r32(p + 20), cursor: G.r32(p + 24), brush: G.r32(p + 28), atom: atomNext++,
      filtered: true };   // rcthook.c p_RegisterClassA: the first class's wndproc goes through filt_wndproc
    H.log(`RegisterClassA(${name}) wndproc ${c.proc.toString(16).padStart(8, '0')}`);
    classes.set(name.toUpperCase(), c);
    return c.atom;
  });

  function newWindow(o) {
    const w = { hwnd: o.hwnd || userHandle(), cls: o.cls, proc: o.proc !== undefined ? o.proc : o.cls.proc, parent: o.parent || 0,
      style: o.style >>> 0, exStyle: o.exStyle >>> 0, x: o.x, y: o.y, w: o.w, h: o.h, text: o.text || '', id: o.id || 0,
      client: null, visible: false, update: null, font: 0, destroyed: false, children: [], dlgProc: 0, dlgResult: 0, user: 0 };
    wins.set(w.hwnd, w);
    if (w.parent && wins.has(w.parent)) wins.get(w.parent).children.push(w.hwnd);
    return w;
  }

  /** Window frame metrics for the styles rct.exe uses (Wine's non-client area). */
  function frame(w) {
    const S = W.SYSTEM_METRICS;
    const caption = (w.style & 0x00C00000) === 0x00C00000 ? S[4] : 0;               // SM_CYCAPTION
    let b = 0;
    if (w.style & 0x00040000) b = S[32];                                           // WS_THICKFRAME: SM_CXFRAME
    else if ((w.style & 0x00C00000) === 0x00C00000 || (w.exStyle & 0x1) || (w.style & 0x80)) b = S[7]; // SM_CXDLGFRAME
    else if (w.style & 0x00800000) b = S[5];                                       // WS_BORDER
    return { l: b, t: b + caption, r: b, b };
  }

  // ---------------------------------------------------------------- message delivery
  /**
   * Send a message to a window's procedure, as Wine does for a same-thread SendMessage. For the
   * class registered by the game, the oracle's filter (rcthook.c filt_wndproc) sits in front of
   * the game's procedure: user input is dropped (TR_MSG_DROP, DefWindowProc instead), everything
   * else is traced (TR_MSG, except WM_TIMER) and logged.
   */
  function send(hwnd, msg, wp = 0, lp = 0) {
    const w = wins.get(hwnd);
    if (!w || w.destroyed && msg !== WM.NCDESTROY && msg !== WM.DESTROY) return 0;
    if (w.cls.filtered) {
      if (!state.mainHwnd) state.mainHwnd = hwnd;
      const q = scriptq[0];
      if (q && q.m === msg && q.w === (wp >>> 0) && q.l === (lp >>> 0)) scriptq.shift();   // posted by a script action: deliver
      else if (isInputMsg(msg)) {
        H.trace.rec(TR.MSG_DROP, H.tick, msg, 0);
        return defWindowProc(hwnd, msg, wp, lp);
      }
      if (msg !== WM.TIMER) H.trace.rec(TR.MSG, H.tick, msg, wp);
      H.log(`msg ${hx(msg)} w=${hx(wp)} l=${hx(lp)} frame ${H.frame}`);
    }
    if (typeof w.proc === 'function') return w.proc(hwnd, msg, wp, lp) >>> 0;
    return H.callback(w.proc, [hwnd, msg, wp, lp], 'wndproc');
  }
  H.sendMessage = send;

  /** Send with a structure on the stack below esp (Wine passes these in its own stack frames). */
  function sendStruct(hwnd, msg, wp, bytes, after) {
    const esp0 = m.esp;
    const n = typeof bytes === 'function' ? bytes(0).length : bytes.length;
    m.esp = (m.esp - ((n + 3) & ~3)) >>> 0;
    const p = m.esp;
    G.put(p, typeof bytes === 'function' ? bytes(p) : bytes);
    const r = send(hwnd, msg, wp, p);
    const out = after ? after(p) : undefined;
    m.esp = esp0;
    return out !== undefined ? out : r;
  }
  const dwords = (a) => { const b = new Uint8Array(4 * a.length); const dv = new DataView(b.buffer); a.forEach((v, i) => dv.setUint32(4 * i, v >>> 0, true)); return b; };

  function defWindowProc(hwnd, msg, wp, lp) {
    const w = wins.get(hwnd);
    switch (msg) {
      case WM.NCCREATE: return 1;
      case WM.NCCALCSIZE: {
        // wParam 0: lParam is the window RECT (screen); it becomes the client RECT
        if (!wp && w && lp) { const f = frame(w); [G.r32(lp) + f.l, G.r32(lp + 4) + f.t, G.r32(lp + 8) - f.r, G.r32(lp + 12) - f.b].forEach((v, i) => G.w32(lp + 4 * i, v)); }
        return 0;
      }
      case WM.NCHITTEST: return 1;                       // HTCLIENT (the pointer is over the client area)
      case WM.SETCURSOR:
        if ((lp & 0xFFFF) === 1 && w && w.cls.cursor) state.cursor = w.cls.cursor;   // Wine: SetCursor(class cursor)
        return (lp & 0xFFFF) === 1 && w && w.cls.cursor ? 1 : 0;
      case WM.ERASEBKGND: return 1;
      case WM.WINDOWPOSCHANGED: {
        const flags = G.r32(lp + 24);
        const c = clientRect(w);
        if (!(flags & 0x1000)) send(hwnd, WM.SIZE, 0, (c.r - c.l) | (c.b - c.t) << 16);        // !SWP_NOCLIENTSIZE
        if (!(flags & 0x800)) send(hwnd, WM.MOVE, 0, ((w.x + c.l) & 0xFFFF) | (w.y + c.t) << 16);  // !SWP_NOCLIENTMOVE
        return 0;
      }
      case WM.NCACTIVATE: return 1;
      case WM.CLOSE: destroyWindow(hwnd); return 0;
      case WM.GETICON: return 0;
      case WM.SETTEXT: if (w) w.text = G.rstr(lp); return 1;
      default: return 0;
    }
  }
  H.def(U('DefWindowProcA'), 4, (h, msg, wp, lp) => defWindowProc(h, msg, wp, lp));

  function clientRect(w) { if (!w.client) { const f = frame(w); w.client = { l: f.l, t: f.t, r: w.w - f.r, b: w.h - f.b }; } return w.client; }

  // ---------------------------------------------------------------- window creation
  // CreateWindowExA for a visible top-level window, in the order Wine 9 sends (hook.log):
  // GETMINMAXINFO, NCCREATE, NCCALCSIZE, CREATE, then ShowWindow: SHOWWINDOW, WINDOWPOSCHANGING,
  // GETICON (ICON_BIG, ICON_SMALL: the X11 driver asks for the window icons), activation
  // (QUERYNEWPALETTE, PALETTEISCHANGING, ACTIVATEAPP, NCACTIVATE, ACTIVATE, IME_SETCONTEXT,
  // SETFOCUS), NCPAINT, ERASEBKGND, WINDOWPOSCHANGED (DefWindowProc: SIZE, MOVE).
  H.def(U('CreateWindowExA'), 12, (ex, pcls, ptitle, style, x, y, cx, cy, parent, menu, hinst, param) => {
    const cname = pcls >>> 16 ? G.rstr(pcls) : '#' + pcls;
    const cls = classes.get(cname.toUpperCase());
    if (!cls) { H.lastError = 1407; return 0; }
    const title = ptitle ? G.rstr(ptitle) : '';
    // Wine fix_exstyle: WS_EX_WINDOWEDGE for a captioned/thick-frame top-level window
    if ((style & 0x00400000) || (ex & 0x1) || ((style & 0x00040000) && !(style & 0xC0000000))) ex = (ex | 0x100) >>> 0;
    const w = newWindow({ hwnd: UW.MAIN_HWND, cls, style, exStyle: ex, x: x | 0, y: y | 0, w: cx | 0, h: cy | 0, text: title, parent });
    // CREATESTRUCTA as Wine passes it: on its stack, followed by copies of the class name and
    // the title (lpszClass, lpszName point at the copies)
    const csBytes = (base) => {
      const pc = base + 48, pn = pc + cname.length + 1;
      const b = new Uint8Array(48 + cname.length + 1 + title.length + 1);
      b.set(dwords([param, hinst, menu, parent, cy, cx, y, x, style, pn, pc, ex]));
      b.set(Buffer.from(cname + '\0' + title + '\0', 'latin1'), 48);
      return b;
    };
    // WM_GETMINMAXINFO: the game fills in track sizes; Wine then clamps the window size
    const S = W.SYSTEM_METRICS;
    const mmi = dwords([0, 0, S[0] + 2 * frame(w).l, S[1] + 2 * frame(w).b, -frame(w).l, -frame(w).b, S[34], S[35], S[59], S[60]]);
    sendStruct(w.hwnd, WM.GETMINMAXINFO, 0, mmi);
    if (!sendStruct(w.hwnd, WM.NCCREATE, 0, csBytes)) { destroyWindow(w.hwnd); return 0; }
    const c = clientRect(w);
    sendStruct(w.hwnd, WM.NCCALCSIZE, 0, dwords([w.x, w.y, w.x + w.w, w.y + w.h]));
    w.needSize = true;
    if ((sendStruct(w.hwnd, WM.CREATE, 0, csBytes) | 0) === -1) { destroyWindow(w.hwnd); return 0; }
    if (style & 0x10000000) showWindow(w);
    return w.hwnd;
  });

  function windowPos(w, flags, rect) { return dwords([w.hwnd, 0, rect ? w.x : 0, rect ? w.y : 0, rect ? w.w : 0, rect ? w.h : 0, flags]); }
  /**
   * Wine NtUserShowWindow(SW_SHOW...) of a hidden window: SHOWWINDOW, WINDOWPOSCHANGING (no
   * move/size: zero rect), GETICON x2 (the X11 driver asks for the icons of a top-level window),
   * activation (unless already active), NCPAINT, ERASEBKGND, WINDOWPOSCHANGED (window rect,
   * SWP_SHOWWINDOW|NOSIZE|NOMOVE|NOCLIENTSIZE|NOCLIENTMOVE), then for a window created visible
   * the deferred WM_SIZE and WM_MOVE (WIN_NEED_SIZE).
   */
  function showWindow(w) {
    send(w.hwnd, WM.SHOWWINDOW, 1, 0);
    sendStruct(w.hwnd, WM.WINDOWPOSCHANGING, 0, windowPos(w, 0x43, false));
    w.visible = true;
    if (!w.parent) {
      send(w.hwnd, WM.GETICON, 1, 0);
      send(w.hwnd, WM.GETICON, 0, 0);
      if (state.active !== w.hwnd) activate(w.hwnd, true);
    }
    send(w.hwnd, WM.NCPAINT, 1, 0);
    send(w.hwnd, WM.ERASEBKGND, w.isDialog ? UW.DIALOG_DC : (H.gdi ? H.gdi.windowDC(w.hwnd) : 0), 0);
    const c = clientRect(w);
    if (!w.isDialog) w.update = { l: 0, t: 0, r: c.r - c.l, b: c.b - c.t };
    sendStruct(w.hwnd, WM.WINDOWPOSCHANGED, 0, windowPos(w, 0x1847, true));
    // the X server reports the pointer over the newly mapped game window (Xvfb's pointer sits at
    // the screen centre): one mouse move, delivered after the first WM_PAINT (hook.log, apitrace)
    if (w.cls.filtered) pointerPending = true;
    if (w.needSize) {
      w.needSize = false;
      send(w.hwnd, WM.SIZE, 0, (c.r - c.l) | (c.b - c.t) << 16);
      send(w.hwnd, WM.MOVE, 0, ((w.x + c.l) & 0xFFFF) | (w.y + c.t) << 16);
    }
  }
  /** Top-level windows in z-order (the most recently shown on top), as HWND_BROADCAST visits them. */
  const topLevels = () => [...wins.values()].filter((w) => !w.parent && !w.destroyed).reverse();

  /**
   * Wine win32u set_active_window(hwnd, focus): deactivate the previous window, palette
   * messages, WM_ACTIVATEAPP when the active thread changes (here: only from no active window),
   * activate, then (focus = TRUE) move the focus into hwnd unless it is already there.
   */
  function activate(hwnd, focus) {
    const old = state.active;
    if (old === hwnd) return;
    if (old && wins.has(old) && !wins.get(old).destroyed) {
      send(old, WM.NCACTIVATE, 0, hwnd);
      send(old, WM.ACTIVATE, 0, hwnd);
    }
    state.active = hwnd;
    if (send(hwnd, WM.QUERYNEWPALETTE, 0, 0)) {
      // SendMessageTimeout(HWND_BROADCAST, WM_PALETTEISCHANGING, hwnd): every top-level window
      for (const w of topLevels()) send(w.hwnd, WM.PALETTEISCHANGING, hwnd, 0);
    }
    if (!old) for (const w of topLevels()) send(w.hwnd, WM.ACTIVATEAPP, 1, 0);
    send(hwnd, WM.NCACTIVATE, 1, old);
    send(hwnd, WM.ACTIVATE, 1, old);
    if (focus && (!state.focus || !isChildOrSelf(hwnd, state.focus))) setFocusWindow(hwnd);
  }
  function isChildOrSelf(parent, h) {
    while (h) { if (h === parent) return true; const w = wins.get(h); h = w ? w.parent : 0; }
    return false;
  }
  /** Wine set_focus_window */
  function setFocusWindow(hwnd) {
    const old = state.focus;
    if (old && wins.has(old) && !wins.get(old).destroyed) {
      send(old, WM.KILLFOCUS, hwnd, 0);
      send(old, WM.IME_SETCONTEXT, 0, 0xC000000F);
    }
    state.focus = hwnd;
    if (hwnd) {
      send(hwnd, WM.IME_SETCONTEXT, 1, 0xC000000F);
      send(hwnd, WM.SETFOCUS, old, 0);
    }
    return old;
  }
  /** Wine NtUserSetFocus: activate the top-level window first (without focus), then focus. */
  function setFocus(hwnd) {
    const old = state.focus;
    if (hwnd === old) return old;
    if (hwnd) {
      let top = hwnd; while (wins.get(top) && wins.get(top).parent) top = wins.get(top).parent;
      if (top !== state.active) { activate(top, false); if (state.active !== top) return 0; }
    }
    return setFocusWindow(hwnd);
  }
  H.def(U('SetFocus'), 1, (h) => setFocus(h));

  /** Wine NtUserDestroyWindow for a top-level window: hide (activating another window), destroy. */
  function destroyWindow(hwnd) {
    const w = wins.get(hwnd);
    if (!w || w.destroyed) { H.lastError = 1400; return 0; }
    if (w.visible) {
      // hide: SWP_HIDEWINDOW|NOACTIVATE|NOZORDER|NOSIZE|NOMOVE, then activate another window
      sendStruct(hwnd, WM.WINDOWPOSCHANGING, 0, windowPos(w, 0x97, false));
      w.visible = false;
      sendStruct(hwnd, WM.WINDOWPOSCHANGED, 0, windowPos(w, 0x1897, true));
      if (state.active === hwnd) {
        const next = topLevels().find((x) => x.visible && x.hwnd !== hwnd);
        if (next) activate(next.hwnd, true); else state.active = 0;
      }
    }
    if (state.focus && isChildOrSelf(hwnd, state.focus)) state.focus = 0;
    send(hwnd, WM.DESTROY, 0, 0);
    for (const c of w.children) { const cw = wins.get(c); if (cw) send(c, WM.DESTROY, 0, 0); }
    for (const c of w.children) { const cw = wins.get(c); if (cw) { send(c, WM.NCDESTROY, 0, 0); cw.destroyed = true; } }
    send(hwnd, WM.NCDESTROY, 0, 0);
    w.destroyed = true;
    return 1;
  }
  H.def(U('DestroyWindow'), 1, (h) => destroyWindow(h));
  H.def(U('IsWindow'), 1, (h) => { const w = wins.get(h); return w && !w.destroyed ? 1 : 0; });

  // ---------------------------------------------------------------- the start-up dialog #101
  require('./dialog').install(H, { wins, state, newWindow, send, sendStruct, dwords, setFocus, showWindow, destroyWindow, defWindowProc, classes, userHandle, WM, frame });

  // ---------------------------------------------------------------- messages
  // Queue model: posted messages (none in practice), then the pending hardware input Wine read
  // from X, then WM_PAINT for a window with an update region, then the pinned WM_TIMER.
  // Wine delivers the window-mapped pointer position (Xvfb's pointer at the screen centre) as a
  // mouse move after the first WM_PAINT: hook.log shows PAINT, NCHITTEST, SETCURSOR, MOUSEMOVE.
  function peek(pmsg, hwnd, lo, hi, remove) {
    let msg = null;
    if (state.queue.length) msg = remove ? state.queue.shift() : state.queue[0];
    else if (pointerPending && paintSeen && state.mainHwnd) {
      const w = wins.get(state.mainHwnd);
      const [sx, sy] = W.X_POINTER || [512, 384];
      const ht = send(w.hwnd, WM.NCHITTEST, 0, (sx & 0xFFFF) | sy << 16);
      send(w.hwnd, WM.SETCURSOR, w.hwnd, ht | WM.MOUSEMOVE << 16);
      const c = clientRect(w);
      msg = { hwnd: w.hwnd, message: WM.MOUSEMOVE, wParam: 0, lParam: ((sx - w.x - c.l) & 0xFFFF) | ((sy - w.y - c.t) & 0xFFFF) << 16, pt: [sx, sy] };
      if (remove) pointerPending = false;
    } else {
      const w = [...wins.values()].find((x) => x.update && x.visible && !x.destroyed);
      if (w) { msg = { hwnd: w.hwnd, message: WM.PAINT, wParam: 0, lParam: 0 }; paintSeen = true; }
      else if (timer.period && ((H.clock.vt - timer.due) | 0) >= 0) {
        // [pin] rcthook.c p_PeekMessageA: WM_TIMER synthesised from the virtual clock
        msg = { hwnd: timer.hwnd, message: WM.TIMER, wParam: timer.id, lParam: 0, pt: [H.input.curX, H.input.curY] };
        if (remove) timer.due = (H.clock.vt + timer.period) >>> 0;
        H.trace.rec(TR.MSG, H.tick, WM.TIMER, timer.id);
      }
    }
    if (!msg) return 0;
    // [pin] rcthook.c p_PeekMessageA: MSG.time = the virtual clock (not advanced), MSG.pt = the
    // virtual cursor; the synthesised WM_TIMER is zero-filled apart from hwnd/message/wParam/time
    const pt = msg.message === WM.TIMER ? [0, 0] : [H.input.curX, H.input.curY];
    [msg.hwnd, msg.message, msg.wParam, msg.lParam, H.clock.vt, pt[0], pt[1]].forEach((v, i) => G.w32(pmsg + 4 * i, v));
    return 1;
  }
  H.def(U('PeekMessageA'), 5, (p, h, lo, hi, rm) => peek(p, h, lo, hi, rm & 1));
  H.def(U('TranslateMessage'), 1, (p) => { const msg = G.r32(p + 4); return msg >= 0x100 && msg <= 0x109 ? 1 : 0; });
  H.def(U('DispatchMessageA'), 1, (p) => {
    const hwnd = G.r32(p), msg = G.r32(p + 4), wp = G.r32(p + 8), lp = G.r32(p + 12);
    if (!hwnd || !wins.has(hwnd)) return 0;
    return send(hwnd, msg, wp, lp);   // WM_PAINT keeps coming until the game validates
  });
  H.def(U('SendMessageA'), 4, (h, msg, wp, lp) => send(h, msg, wp, lp));
  H.def(U('GetUpdateRect'), 3, (h, pr, erase) => {
    const w = wins.get(h);
    const u = w && w.update;
    if (pr) [u ? u.l : 0, u ? u.t : 0, u ? u.r : 0, u ? u.b : 0].forEach((v, i) => G.w32(pr + 4 * i, v));
    return u ? 1 : 0;
  });
  H.def(U('GetUpdateRgn'), 3, (h, rgn, erase) => {
    const w = wins.get(h);
    if (H.gdi) H.gdi.setRegion(rgn, w && w.update);
    return w && w.update ? 2 : 1;    // SIMPLEREGION : NULLREGION
  });
  H.def(U('ValidateRect'), 2, (h, pr) => { const w = wins.get(h); if (w && !pr) w.update = null; return 1; });

  // timers: [pin] no OS timer; WM_TIMER synthesised from the virtual clock (never called in practice)
  const timer = { id: 0, period: 0, due: 0, hwnd: 0 };
  H.def(U('SetTimer'), 4, (h, id, ms, fn) => {
    H.log(`SetTimer(${hx(h)},${id},${ms},${hx(fn)}) frame ${H.frame}`);
    Object.assign(timer, { hwnd: h, id, period: ms, due: (H.clock.vt + ms) >>> 0 });
    return id;
  });
  H.def(U('KillTimer'), 2, (h, id) => { H.log(`KillTimer(${hx(h)},${id}) frame ${H.frame}`); if (id === timer.id) timer.period = 0; return 1; });

  // ---------------------------------------------------------------- cursor, input pins
  H.def(U('GetCursorPos'), 1, (p) => { G.w32(p, H.input.curX); G.w32(p + 4, H.input.curY); return 1; });
  H.def(U('SetCursorPos'), 2, (x, y) => { H.input.curX = x | 0; H.input.curY = y | 0; return 1; });
  H.def(U('SetCursor'), 1, (c) => { const o = state.cursor; state.cursor = c; return o; });
  const cursors = new Map();
  const loadUserImage = (kind, hinst, id) => {
    const key = `${kind}:${hinst >>> 0}:${id >>> 16 ? G.rstr(id).toUpperCase() : id}`;
    if (!cursors.has(key)) {
      const known = (UW.IMAGES || {})[key];
      cursors.set(key, known !== undefined ? known : userHandle());
    }
    return cursors.get(key);
  };
  H.def(U('LoadCursorA'), 2, (hinst, id) => loadUserImage('cursor', hinst, id));
  H.def(U('LoadIconA'), 2, (hinst, id) => loadUserImage('icon', hinst, id));
  H.def(U('GetSystemMetrics'), 1, (i) => (i < W.SYSTEM_METRICS.length ? W.SYSTEM_METRICS[i] : 0));
  H.def(U('GetKeyboardType'), 1, (i) => (i < 3 ? W.KEYBOARD_TYPE[i] : 0));
  H.def(U('SystemParametersInfoA'), 4, (action, ui, pv, win) => {
    if (action === 3) { W.SPI_GETMOUSE.forEach((v, i) => G.w32(pv + 4 * i, v)); return 1; }   // SPI_GETMOUSE
    throw new Error(`SystemParametersInfoA action ${action} is not implemented`);
  });

  // ---------------------------------------------------------------- DCs (handles from gdi32.js)
  H.def(U('GetDC'), 1, (h) => H.gdi.getDC(h));
  H.def(U('ReleaseDC'), 2, (h, dc) => H.gdi.releaseDC(h, dc));

  // ---------------------------------------------------------------- modal UI: the oracle fails fast
  H.def(U('MessageBoxA'), 4, (h, text, cap, t) => { throw H.dialogFatal('MessageBoxA', `[${cap ? G.rstr(cap) : ''}] ${text ? G.rstr(text) : ''}`); });
  H.def(U('DialogBoxParamA'), 5, (i, tmpl, h, p, l) => { throw H.dialogFatal('DialogBoxParamA', tmpl >>> 16 ? G.rstr(tmpl) : `template #${tmpl}`); });

  H.userInternals = { send, defWindowProc, frame, clientRect, isInputMsg, MSGNAME };
}

module.exports = { install, WM, isInputMsg };
