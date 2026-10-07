'use strict';
// Input-script parser, a faithful port of load_script() in oracle/rcthook.c (format:
// oracle/README.md). Same tokenisation (fgets lines of at most 1023 characters, '#' comments,
// strtok on " \t\r\n", at most 32 tokens), same strtoul(…, 0) number syntax (32-bit unsigned
// long, as under mingw), same fatal conditions and messages.

const W_FRAME = 0, W_TICK = 1;
const A = Object.freeze({ QUIT: 0, CMD: 1, LOAD: 2, KEY: 3, CURSOR: 4, DUMP: 5, CALL: 6, POKE: 7, SHOT: 8, FB: 9, MOUSE: 10,
  FILE: 11, CHAR: 12, DIMOUSE: 13, MOVE: 14 });
const REG_NAMES = ['edi', 'esi', 'ebp', 'esp', 'ebx', 'edx', 'ecx', 'eax', 'eflags'];

class ScriptError extends Error {
  constructor(why, line) { super(`${why} (script line ${line})`); this.why = why; this.line = line; }
}

/** The number syntax of C strtoul/strtol with base 0: sign, then 0x hex, 0 octal or decimal. */
function parseNum(s) {
  let i = 0;
  while (i < s.length && ' \t\n\v\f\r'.includes(s[i])) i++;
  let neg = false;
  if (s[i] === '+' || s[i] === '-') { neg = s[i] === '-'; i++; }
  let base = 10;
  if (s[i] === '0') {
    if ((s[i + 1] === 'x' || s[i + 1] === 'X') && /[0-9a-fA-F]/.test(s[i + 2] || '')) { base = 16; i += 2; }
    else base = 8;
  }
  let mag = 0, any = false;
  for (; i < s.length; i++) {
    const d = parseInt(s[i], 36);
    if (Number.isNaN(d) || d >= base) break;
    any = true;
    mag = Math.min(mag * base + d, 2 ** 53);   // saturates far above any 32-bit range
  }
  return { neg, mag, any };
}
/** C strtoul(s, NULL, 0) with a 32-bit unsigned long. Returns a uint32 number. */
function strtoul(s) {
  const { neg, mag, any } = parseNum(s);
  if (!any) return 0;
  if (mag > 0xFFFFFFFF) return 0xFFFFFFFF;          // ERANGE: ULONG_MAX (the sign is not applied)
  return neg ? (-mag) >>> 0 : mag >>> 0;
}
/** C strtol(s, NULL, 0) with a 32-bit long, returned as its uint32 bit pattern. */
function strtol(s) {
  const { neg, mag, any } = parseNum(s);
  if (!any) return 0;
  if (!neg) return mag > 0x7FFFFFFF ? 0x7FFFFFFF : mag;   // ERANGE: LONG_MAX
  return mag > 0x80000000 ? 0x80000000 : (-mag) >>> 0;   // ERANGE: LONG_MIN
}

function emptyRegs() { return { edi: 0, esi: 0, ebp: 0, esp: 0, ebx: 0, edx: 0, ecx: 0, eax: 0, eflags: 0 }; }

function parseReg(tok, r) {
  const eq = tok.indexOf('=');
  if (eq < 0) return false;
  const name = tok.slice(0, eq);
  if (!REG_NAMES.includes(name)) return false;
  r[name] = strtoul(tok.slice(eq + 1));
  return true;
}

/** Split text into lines the way fgets(line, 1024, f) reads them (at most 1023 chars each). */
function fgetsLines(text) {
  const out = [];
  let i = 0;
  while (i < text.length) {
    const nl = text.indexOf('\n', i);
    const end = nl < 0 ? text.length : nl + 1;
    let j = i;
    while (j < end) { const k = Math.min(end, j + 1023); out.push(text.slice(j, k)); j = k; }
    i = end;
  }
  return out;
}

/**
 * Parse a script. Returns {seed: number|undefined, actions: [...], log: [lines]}.
 * Throws ScriptError for the conditions rcthook.c treats as fatal.
 */
function parseScript(text) {
  const actions = [];
  const log = [];
  let seed, quantum;
  let ln = 0;
  for (const raw of fgetsLines(text)) {
    ln++;
    let line = raw;
    const c = line.indexOf('#'); if (c >= 0) line = line.slice(0, c);
    // strtok also stops at an embedded NUL
    const z = line.indexOf('\0'); if (z >= 0) line = line.slice(0, z);
    const tok = line.split(/[ \t\r\n]+/).filter((t) => t.length).slice(0, 32);
    const nt = tok.length;
    if (!nt) continue;
    if (tok[0] === 'seed' && nt >= 2) {
      seed = strtoul(tok[1]);
      log.push(`script:${ln}: seed: virtual clock starts at ${seed}`);
      continue;
    }
    if (tok[0] === 'quantum' && nt >= 2) {
      quantum = strtoul(tok[1]);
      if (!quantum) throw new ScriptError('quantum must be at least 1', ln);
      log.push(`script:${ln}: quantum ${quantum}`);
      continue;
    }
    if (nt < 3) throw new ScriptError('action too short', ln);
    if (tok[0] !== 'tick' && tok[0] !== 'frame') throw new ScriptError("time must be 'tick N' or 'frame [+]N'", ln);
    const a = { whenKind: tok[0] === 'tick' ? W_TICK : W_FRAME, when: 0, action: -1, r: emptyRegs(), arg: 0, arg2: 0, line: ln, rel: false, text: '' };
    a.rel = tok[1][0] === '+';
    a.when = strtoul(tok[1].slice(a.rel ? 1 : 0));
    const v = tok[2];
    if (v === 'quit') a.action = A.QUIT;
    else if (v === 'dump') a.action = A.DUMP;
    else if (v === 'shot') a.action = A.SHOT;
    else if (v === 'fb') a.action = A.FB;
    else if (v === 'load' && nt >= 4) { a.action = A.LOAD; a.arg = strtoul(tok[3]); }
    else if (v === 'cmd' && nt >= 4) {
      a.action = A.CMD; a.arg = strtoul(tok[3]);
      for (let i = 4; i < nt; i++) parseReg(tok[i], a.r);
    } else if (v === 'call' && nt >= 4) {
      a.action = A.CALL; a.arg = strtoul(tok[3]);
      for (let i = 4; i < nt; i++) parseReg(tok[i], a.r);
    } else if (v === 'key' && nt >= 5) {
      a.action = A.KEY; a.arg = strtoul(tok[3]); a.arg2 = strtoul(tok[4]);
    } else if (v === 'cursor' && nt >= 5) {
      a.action = A.CURSOR; a.arg = strtoul(tok[3]); a.arg2 = strtoul(tok[4]);
    } else if (v === 'mouse' && nt >= 6) {
      a.action = A.MOUSE; a.arg = strtoul(tok[3]); a.arg2 = strtoul(tok[4]); a.r.eax = strtoul(tok[5]);
    } else if (v === 'file' && nt >= 4) {
      a.action = A.FILE; a.text = tok[3].slice(0, 259);
    } else if (v === 'char' && nt >= 4) {
      a.action = A.CHAR; a.arg = tok[3].length === 1 ? tok[3].charCodeAt(0) & 0xFF : strtoul(tok[3]);
    } else if (v === 'move' && nt >= 5) {
      a.action = A.MOVE; a.arg = strtoul(tok[3]); a.arg2 = strtoul(tok[4]);
    } else if (v === 'dimouse' && nt >= 6) {
      a.action = A.DIMOUSE; a.arg = strtol(tok[3]); a.arg2 = strtol(tok[4]); a.r.eax = strtoul(tok[5]);
    } else if (v === 'poke' && nt >= 5) {
      a.action = A.POKE; a.arg = strtoul(tok[3]); a.arg2 = strtoul(tok[4]);
    } else throw new ScriptError('unknown action or missing arguments', ln);
    actions.push(a);
  }
  return { seed, quantum, actions, log };
}

module.exports = { parseScript, strtoul, strtol, ScriptError, W_FRAME, W_TICK, A, REG_NAMES };
