'use strict';
// The oracle's virtual clock (oracle/rcthook.c p_timeGetTime, p_GetTickCount, p_Sleep,
// p_GetSystemTime). All arithmetic is uint32, as in the hook.

const VT_BASE = 5000000;
// SYSTEMTIME {2000, 1, 4 (Thursday), 13, 12, 0, 0, 0} as a JS epoch value
const SYSTIME_BASE_MS = Date.UTC(2000, 0, 13, 12, 0, 0, 0);

class VirtualClock {
  constructor(start = VT_BASE, quantum = 1) {
    this.vt = start >>> 0;
    this.quantum = quantum >>> 0;
  }
  /** timeGetTime / GetTickCount: return the clock, then advance it by the quantum */
  query() { const t = this.vt; this.vt = (this.vt + this.quantum) >>> 0; return t; }
  /** Sleep(ms): advance, never block */
  sleep(ms) { this.vt = (this.vt + (ms >>> 0)) >>> 0; }
  /**
   * GetSystemTime: 2000-01-13 12:00:00.000 + (uint32)(vt - VT_BASE) ms, via FILETIME arithmetic
   * (so a seed below VT_BASE wraps to ~49.7 days later, exactly as the hook computes it).
   * Returns the eight SYSTEMTIME words.
   */
  systemTime() {
    const ms = (this.vt - VT_BASE) >>> 0;
    const d = new Date(SYSTIME_BASE_MS + ms);
    return {
      wYear: d.getUTCFullYear(), wMonth: d.getUTCMonth() + 1, wDayOfWeek: d.getUTCDay(), wDay: d.getUTCDate(),
      wHour: d.getUTCHours(), wMinute: d.getUTCMinutes(), wSecond: d.getUTCSeconds(), wMilliseconds: d.getUTCMilliseconds(),
    };
  }
}

module.exports = { VirtualClock, VT_BASE };
