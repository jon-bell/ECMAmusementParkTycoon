'use strict';
// API trace emitted by the host in the oracle's format (oracle/README.md "API trace", rendering
// as oracle/apitrace.c, signatures from oracle/apisig.txt), so that tools/apitrace.py diff can
// find the first call where the host's answer differs from Wine's. A debugging instrument:
// enabled with RCTHOOK_SPIKE=apitrace (as the oracle) or the host option apitrace: true; it reads
// and writes no game state.
const fs = require('fs');
const path = require('path');
const G = require('./guestmem');

const GAME_LO = 0x401000, GAME_HI = 0x9BD000, MAXARGS = 14;
const hex = (v) => (v >>> 0).toString(16);

function parseLen(s) {
  const l = { type: '', v: 0, mul: 1 };
  let m;
  if ((m = /^\*(\d+)(.*)$/.exec(s))) { l.type = 'deref'; l.v = +m[1]; s = m[2]; }
  else if ((m = /^r(.*)$/.exec(s))) { l.type = 'ret'; s = m[1]; }
  else if ((m = /^=(\d+)(.*)$/.exec(s))) { l.type = 'const'; l.v = +m[1]; s = m[2]; }
  else if ((m = /^d(\d+)(.*)$/.exec(s))) { l.type = 'dib'; l.v = +m[1]; s = m[2]; }
  else if ((m = /^(\d+)(.*)$/.exec(s))) { l.type = 'arg'; l.v = +m[1]; s = m[2]; }
  else throw new Error(`apisig: bad length ${s}`);
  if (s[0] === 'x') l.mul = parseInt(s.slice(1), 10);
  return l;
}
function parseKind(t, isRet) {
  const k = { dir: 'in', base: '', sub: null, len: null, cond: '' };
  if (!isRet) { if (t.startsWith('io')) { k.dir = 'io'; t = t.slice(2); } else if (t[0] === 'o') { k.dir = 'out'; t = t.slice(1); } }
  const q = /\?(0|-1)?$/.exec(t);
  if (q && !isRet) { k.cond = q[0]; t = t.slice(0, q.index); }
  const at = t.indexOf('@');
  if (at >= 0) { k.len = parseLen(t.slice(at + 1)); t = t.slice(0, at); }
  if (t.startsWith('cb:')) { k.base = 'cb'; k.sub = t.slice(3); }
  else if (t.startsWith('S:')) { k.base = 'struct'; k.sub = t.slice(2); }
  else if (t.startsWith('I:')) { k.base = 'iface'; k.sub = t.slice(2); }
  else k.base = t;
  if (k.base === 'x' && k.len) k.base = 'hex';
  return k;
}
function loadSigs(text) {
  const sigs = new Map(), structs = new Map(), msgs = new Map();
  for (let line of text.split('\n')) {
    line = line.replace(/(^|[ \t])#.*$/, '');
    const tok = line.split(/[ \t\r]+/).filter(Boolean);
    if (!tok.length) continue;
    if (tok[0] === 'struct') {
      let size = 0; const str = [], chr = [], unused = [];
      for (const f of tok.slice(2)) {
        const n = parseInt(f.slice(1), 10);
        if (f[0] === 's') str.push(size);
        if (f[0] === 'c') chr.push([size, n]);
        if (f[0] === 'u') unused.push([size, n]);
        size += n;
      }
      structs.set(tok[1], { size, str, chr, unused });
    } else if (tok[0] === 'msg') msgs.set(parseInt(tok[1], 16), { io: tok[2] === 'io', kind: tok[3] });
    else if (tok[0] === 'fn' || tok[0] === 'cb') {
      const cb = tok[0] === 'cb';
      const i = cb ? 2 : 3;
      sigs.set(tok[1], { name: tok[1], cdecl: !cb && tok[2] === 'cdecl', ret: parseKind(tok[i], true), args: tok.slice(i + 1).map((t) => parseKind(t, false)) });
    }
  }
  return { sigs, structs, msgs };
}

class ApiTrace {
  constructor(H, outPath) {
    this.H = H;
    const S = loadSigs(fs.readFileSync(path.join(__dirname, '../../oracle/apisig.txt'), 'utf8'));
    Object.assign(this, S);
    this.fd = fs.openSync(outPath, 'w');
    this.buf = [];
    this.depth = 0;
    this.stack = [];
    this.records = 0;
    this.line('# apitrace 1');
  }
  line(s) { this.buf.push(s); this.records++; if (this.buf.length >= 4096) this.flush(); }
  flush() { if (this.buf.length) { fs.writeSync(this.fd, this.buf.join('\n') + '\n'); this.buf = []; } }
  close() {
    this.line(`# end records=${this.records} errors=0 other_thread_calls=0 open=${this.depth}`);
    this.flush(); fs.closeSync(this.fd);
  }
  get ft() { const h = this.H.hooks; return `${hex(h ? h.frame : 0)} ${hex(h ? h.tick : 0)}`; }

  // ---------------------------------------------------------------- memory
  readable(p, n) {
    p >>>= 0;
    if (!p || p + n > 0x100000000) return false;
    const M = G.M;
    for (let a = p & ~0xFFF; a < p + Math.max(n, 1); a += 0x1000) if (!(M.protOf(a) & 1)) return false;
    return true;
  }
  rStr(p, n, stopNul) {
    if (!p) return '0';
    if (p < 0x10000) return '#' + hex(p);
    let s = hex(p) + '=';
    const nul = n === 0xFFFFFFFF || stopNul; if (n === 0xFFFFFFFF) n = 1024;
    const cap = Math.min(n, 1024);
    s += '"';
    let i = 0;
    for (; i < cap; i++) {
      if ((((p + i) & 0xFFF) === 0 || i === 0) && !this.readable(p + i, 1)) return s + '"!';
      const c = G.r8(p + i);
      if (nul && !c) break;
      s += litOk(c) ? String.fromCharCode(c) : '\\x' + c.toString(16).padStart(2, '0');
    }
    s += '"';
    if (i === cap && n > cap) s += '~';
    return s;
  }
  rWStr(p, n, stopNul) {
    if (!p) return '0';
    let s = hex(p) + '=L"';
    const nul = n === 0xFFFFFFFF || stopNul; if (n === 0xFFFFFFFF) n = 1024;
    const cap = Math.min(n, 1024);
    let i = 0;
    for (; i < cap; i++) {
      const a = p + 2 * i;
      if (((a & 0xFFF) === 0 || (a & 0xFFF) === 0xFFF || i === 0) && !this.readable(a, 2)) return s + '"!';
      const c = G.r16(a);
      if (nul && !c) break;
      s += c < 0x80 && litOk(c) ? String.fromCharCode(c) : '\\u' + c.toString(16).padStart(4, '0');
    }
    s += '"';
    if (i === cap && n > cap) s += '~';
    return s;
  }
  hexBytes(p, n) {
    if (!this.readable(p, n)) return '{!}';
    let s = '{';
    for (let i = 0; i < n; i++) s += G.r8(p + i).toString(16).padStart(2, '0');
    return s + '}';
  }
  rBuf(p, n) {
    if (!p) return '0';
    if (n > 0x4000000) return hex(p) + '=?';
    if (!this.readable(p, n)) return hex(p) + '=!';
    return `${hex(p)}=${n}:${fnv(G.bytes(p, n))}`;
  }
  rStruct(p, name) {
    if (!p) return '0';
    const st = this.structs.get(name);
    if (!st) return hex(p);
    if (!this.readable(p, st.size)) return hex(p) + '={!}';
    // char[N] fields: bytes after the first NUL are not part of the string; shown as ".."
    let s = hex(p) + '={';
    for (let i = 0; i < st.size; i++) {
      let dead = st.unused.some(([o, n]) => i >= o && i < o + n);   // uN: bytes the callee leaves undefined
      for (const [o, n] of st.chr) {
        if (i > o && i < o + n) { for (let j = o; j < i; j++) if (!G.r8(p + j)) { dead = true; break; } }
      }
      s += dead ? '..' : G.r8(p + i).toString(16).padStart(2, '0');
    }
    s += '}';
    for (const o of st.str) s += ',' + this.rStr(G.r32(p + o), 0xFFFFFFFF, false);
    return s;
  }
  rGuid(p) {
    if (!p) return '0';
    if (!this.readable(p, 16)) return hex(p) + '=!';
    const b = (i) => G.r8(p + i).toString(16).padStart(2, '0');
    return `${hex(p)}={${G.r32(p).toString(16).padStart(8, '0')}-${G.r16(p + 4).toString(16).padStart(4, '0')}-${G.r16(p + 6).toString(16).padStart(4, '0')}-${b(8)}${b(9)}-${b(10)}${b(11)}${b(12)}${b(13)}${b(14)}${b(15)}}`;
  }
  bmiColorsLen(p, usage) {
    if (!this.readable(p, 40)) return 0;
    const bpp = G.r16(p + 14), comp = G.r32(p + 16), used = G.r32(p + 32);
    const n = used || (bpp <= 8 ? 1 << bpp : 0);
    if (comp === 3) return 12;
    return n * (usage === 1 ? 2 : 4);
  }
  dibSize(p) {
    if (!this.readable(p, 40)) return 0;
    const w = G.r32(p + 4), h = Math.abs(G.s32(p + 8)), bpp = G.r16(p + 14);
    return (h * ((((w * bpp) >>> 0) + 31) >>> 5) * 4) >>> 0;
  }
  rBmi(p, usage) {
    if (!p) return '0';
    let s = hex(p) + '=' + this.hexBytes(p, 40) + ',';
    const n = this.bmiColorsLen(p, usage);
    if (!this.readable(p + 40, n)) return s + '!';
    return s + `${n}:${fnv(G.bytes(p + 40, n))}`;
  }
  rLpal(p) {
    if (!p) return '0';
    if (!this.readable(p, 4)) return hex(p) + '=!';
    return hex(p) + '=' + this.hexBytes(p, 4 + 4 * G.r16(p + 2));
  }
  evalLen(l, args, ret) {
    let v;
    switch (l.type) {
      case 'arg': v = args[l.v - 1]; break;
      case 'deref': { const p = args[l.v - 1]; if (!p || !this.readable(p, 4)) return null; v = G.r32(p); break; }
      case 'ret': v = ret; break;
      case 'const': v = l.v; break;
      case 'dib': v = this.dibSize(args[l.v - 1]); break;
      default: return null;
    }
    if (v === 0xFFFFFFFF) return v;
    return (v * l.mul) >>> 0;
  }
  rMsgl(msg, wp, lp, after) {
    const k = this.msgs.get(msg);
    if (k && !(after && !k.io)) {
      if (k.kind === 's') return this.rStr(lp, 0xFFFFFFFF, false);
      if (k.kind === 'NCCALC') return this.rStruct(lp, wp ? 'NCCALCSIZE_PARAMS' : 'RECT');
      return this.rStruct(lp, k.kind);
    }
    return hex(lp);
  }
  rArg(k, i, args, ret, phase) {
    const v = args[i] >>> 0;
    if (phase === 0 && k.dir === 'out') return hex(v);
    // out/io content is rendered only when the call's result says it was written
    if (phase === 1 && v && ((k.cond === '?' && !ret) || (k.cond === '?0' && ret) || (k.cond === '?-1' && ret === 0xFFFFFFFF))) return hex(v) + '=-';
    let n;
    switch (k.base) {
      case 'x': case 'h': case 'p': case 'cb': return hex(v);
      case 's': n = k.len ? this.evalLen(k.len, args, ret) : 0xFFFFFFFF; return this.rStr(v, n === null ? 0 : n, k.dir !== 'in');
      case 'ws': n = k.len ? this.evalLen(k.len, args, ret) : 0xFFFFFFFF; return this.rWStr(v, n === null ? 0 : n, k.dir !== 'in');
      case 'g': return this.rGuid(v);
      case 'struct': return this.rStruct(v, k.sub);
      case 'lpal': return this.rLpal(v);
      case 'bmi': return this.rBmi(v, k.len && k.len.v >= 1 ? args[k.len.v - 1] : 0);
      case 'msgl': return this.rMsgl(args[1], args[2], v, phase);
      case 'b': n = this.evalLen(k.len, args, ret); if (n === null || n === 0xFFFFFFFF) return v ? hex(v) + '=?' : '0'; return this.rBuf(v, n);
      case 'hex': n = this.evalLen(k.len, args, ret); if (!v) return '0'; if (n === null || n > 4096) return hex(v) + '=?'; return hex(v) + '=' + this.hexBytes(v, n);
      case 'dx': case 'dh': case 'dp': case 'iface':
        if (!v) return '0';
        return hex(v) + '=' + (this.readable(v, 4) ? hex(G.r32(v)) : '!');
      case 'da':
        if (!v) return '0';
        return hex(v) + '=' + (this.readable(v, 4) ? hex(G.r32(v)) : '!') + ':' + this.evalLen(k.len, args, ret);
      default: return hex(v);
    }
  }
  rRet(k, args, ret) {
    switch (k.base) {
      case 'v': return '-';
      case 's': return this.rStr(ret, 0xFFFFFFFF, false);
      case 'a': return hex(ret) + ':' + this.evalLen(k.len, args, ret);
      case 'eas': case 'ews': {
        if (!ret) return '0';
        const w = k.base === 'ews' ? 2 : 1;
        let n = 0;
        while (n < 0x100000 && this.readable(ret + n, 2 * w)) {
          const z = w === 2 ? !G.r16(ret + n) && !G.r16(ret + n + 2) : !G.r8(ret + n) && !G.r8(ret + n + 1);
          if (z) { n += 2 * w; break; }
          n += w;
        }
        return this.rBuf(ret, n);
      }
      default: return hex(ret);
    }
  }

  // ---------------------------------------------------------------- records
  entry(m) {
    const r = [m.eax, m.ebx, m.ecx, m.edx, m.esi, m.edi, m.ebp, m.getEflags(), G.r32(m.esp), G.r32(m.esp + 4), G.r32(m.esp + 8), G.r32(m.esp + 12)];
    this.line(`B 0 0 0 entry ${hex(m.eip)} ${hex(m.esp)} ${r.map(hex).join(' ')}`);
  }
  /** Before a host function runs: returns a token for ret(), or null if not traced. */
  call(m, name) {
    const ret = G.r32(m.esp);
    if (ret < GAME_LO || ret >= GAME_HI) return null;
    const sig = this.sigs.get(name);
    const args = []; for (let i = 0; i < MAXARGS; i++) args.push(this.readable(m.esp + 4 + 4 * i, 4) ? G.r32(m.esp + 4 + 4 * i) : 0);
    let s = `C ${this.ft} ${hex(this.depth)} ${hex(ret)} ${hex(m.esp)} ${name}`;
    if (sig) for (let i = 0; i < sig.args.length; i++) s += ' ' + this.rArg(sig.args[i], i, args, 0, 0);
    else s += ' ?';
    this.line(s);
    const t = { name, sig, args, depth: this.depth };
    this.depth++;
    return t;
  }
  ret(t, eax) {
    this.depth = t.depth;
    let s = `R ${hex(t.depth)} ${t.name} `;
    if (t.sig) {
      s += this.rRet(t.sig.ret, t.args, eax >>> 0);
      t.sig.args.forEach((k, i) => { if (k.dir !== 'in') s += ' ' + this.rArg(k, i, t.args, eax >>> 0, 1); });
    } else s += hex(eax);
    this.line(s);
  }
  cbEnter(kind, target, esp, args) {
    const sig = this.sigs.get(kind);
    let s = `B ${this.ft} ${hex(this.depth)} ${kind} ${hex(target)} ${hex(esp)}`;
    if (sig) for (let i = 0; i < sig.args.length; i++) s += ' ' + this.rArg(sig.args[i], i, args, 0, 0);
    this.line(s);
    const t = { kind, sig, args, depth: this.depth };
    this.depth++;
    return t;
  }
  cbLeave(t, ret) {
    this.depth = t.depth;
    let s = `E ${hex(t.depth)} ${t.kind} `;
    if (t.sig) {
      s += this.rRet(t.sig.ret, t.args, ret >>> 0);
      t.sig.args.forEach((k, i) => {
        if (k.dir === 'in' && k.base !== 'msgl') return;
        if (k.base === 'msgl') { const mk = this.msgs.get(t.args[1]); if (!mk || !mk.io) return; }
        s += ' ' + this.rArg(k, i, t.args, ret >>> 0, 1);
      });
    } else s += hex(ret);
    this.line(s);
  }
  drop(msg, wp, lp) { this.line(`# drop ${this.ft} ${hex(this.depth)} msg=${hex(msg)} w=${hex(wp)} l=${hex(lp)}`); }
}
function litOk(c) { return c > 0x20 && c < 0x7f && c !== 0x22 && c !== 0x5c && c !== 0x7b && c !== 0x7d && c !== 0x2c; }
function fnv(bytes) {
  let lo = 0x84222325, hi = 0xcbf29ce4;
  for (let i = 0; i < bytes.length; i++) {
    const x = (lo ^ bytes[i]) >>> 0, t = x * 0x1b3;
    hi = (Math.imul(hi, 0x1b3) + Math.floor(t / 4294967296) + (x << 8)) >>> 0;
    lo = t >>> 0;
  }
  return hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
}

module.exports = { ApiTrace, loadSigs, fnv };
