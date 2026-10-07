'use strict';
// WINMM: the virtual clock (oracle pin), the sound timer (pinned: never started) and music
// (no MIDI device in the oracle's environment: Wine's answers in wine-answers.js).
const G = require('./guestmem');
const { TR } = require('./trace');

function install(H) {
  const W = H.W;
  const M = (n) => 'WINMM.DLL!' + n;
  H.def(M('timeGetTime'), 0, () => H.clock.query());                               // [pin]
  H.def(M('timeBeginPeriod'), 1, () => W.TIME_BEGIN_PERIOD);
  H.def(M('timeSetEvent'), 5, (delay, res, cb, user, flags) => {                    // [pin] not started
    H.log(`timeSetEvent(${delay},${res},0x${cb.toString(16)},${user.toString(16)},${flags}) frame ${H.frame}: not started`);
    H.trace.rec(TR.NOTE, H.tick, 1, cb);
    return 0x7777;
  });
  H.def(M('timeKillEvent'), 1, () => 0);                                              // [pin]
  H.def(M('midiOutGetNumDevs'), 0, () => W.MIDI_NUM_DEVS);
  // no device: the caller's MIDIOUTCAPSA is left untouched
  H.def(M('midiOutGetDevCapsA'), 3, (id, p, n) => W.MIDI_CAPS_RESULT);
  H.def(M('midiOutGetVolume'), 2, (h, pv) => {
    if ((h >>> 0) !== 0xFFFFFFFF) return W.MIDI_CAPS_RESULT;
    if (pv) G.w32(pv, W.MIDI_MAPPER_VOLUME.volume);
    return W.MIDI_MAPPER_VOLUME.result;
  });
  H.def(M('mciSendStringA'), 4, (pcmd, pret, n, hwnd) => {
    const cmd = G.rstr(pcmd);
    H.log(`mciSendStringA(${cmd}) frame ${H.frame}`);
    if (cmd === 'close all') return 0;
    if (/^open .* type sequencer alias MUSIC$/.test(cmd)) return 275;   // [probe] no sequencer to open it with
    throw new Error(`mciSendStringA(${cmd}): Wine's answer not measured`);
  });
}
module.exports = { install };
