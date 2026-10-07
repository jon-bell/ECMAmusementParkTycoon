'use strict';
// COMDLG32: [pin] rcthook.c file_dialog(): a common file dialog is never shown. A script
// `file <name>` action answers the next one with <game directory>\Saved Games\<name>
// (TR_NOTE 4 value 1); without one the dialog is cancelled (TR_NOTE 4 value 0, FALSE).
const G = require('./guestmem');
const { TR } = require('./trace');

function install(H) {
  const W = H.W;
  // OPENFILENAMEA: lpstrFile +28, nMaxFile +32, lpstrFileTitle +36, nMaxFileTitle +40,
  // lpstrInitialDir +44, lpstrTitle +48, nFileOffset +56 (WORD), nFileExtension +58 (WORD)
  function fileDialog(o, what) {
    const title = o && G.r32(o + 48) ? G.rstr(G.r32(o + 48)) : '-';
    const dir0 = o && G.r32(o + 44) ? G.rstr(G.r32(o + 44)) : '-';
    H.log(`${what}: title ${title} initial dir ${dir0} (frame ${H.frame} tick ${H.tick})`);
    const ans = H.input.fileAnswer;
    if (ans === null || !o || !G.r32(o + 28)) {
      H.log(`${what}: no script answer: cancelled`);
      H.trace.rec(TR.NOTE, H.tick, 4, 0);
      return 0;
    }
    H.input.fileAnswer = null;
    const dir = W.MODULE_FILE_NAME.slice(0, W.MODULE_FILE_NAME.lastIndexOf('\\'));
    const p = `${dir}\\Saved Games\\${ans}`;
    if (p.length + 1 > G.r32(o + 32)) { H.log(`${what}: answer too long`); H.trace.rec(TR.NOTE, H.tick, 4, 0); return 0; }
    G.wstr(G.r32(o + 28), p);
    const off = p.length - ans.length;
    G.w16(o + 56, off);
    const dot = ans.lastIndexOf('.');
    G.w16(o + 58, dot >= 0 ? off + dot + 1 : 0);
    const pt = G.r32(o + 36);
    if (pt && G.r32(o + 40) > ans.length) G.wstr(pt, ans);
    H.log(`${what}: answered ${p}`);
    H.trace.rec(TR.NOTE, H.tick, 4, 1);
    return 1;
  }
  H.def('COMDLG32.DLL!GetOpenFileNameA', 1, (o) => fileDialog(o, 'GetOpenFileNameA'));
  H.def('COMDLG32.DLL!GetSaveFileNameA', 1, (o) => fileDialog(o, 'GetSaveFileNameA'));
}
module.exports = { install };
