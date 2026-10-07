'use strict';
// Directory enumeration as the oracle presents it to the game (oracle/rcthook.c
// p_FindFirstFileA/p_FindNextFileA on top of Wine 9.0's FindFirstFileA):
//   * Wine's mask matching (ntdll unix/file.c match_filename) against the long name, then the
//     short name;
//   * Wine's short names: none for a legal 8.3 name (is_legal_8dot3_name), otherwise the hashed
//     alias (hash_short_file_name), e.g. "Saved Games" -> "SAVE~YWG";
//   * the hook: entries sorted by strcmp of the long name, all three timestamps pinned to
//     FILETIME {0x5c2d8000, 0x01bf5d9b}, and on drive D: the Windows-style alias (cd_alias);
//   * the result stored like put_find(): fixed fields, dwReserved0/1 = 0, and the two names
//     up to and including their NUL; the rest of the caller's buffers is left untouched.

const FIND_TIME_LO = 0x5c2d8000, FIND_TIME_HI = 0x01bf5d9b;   // 2000-01-13, rcthook.c
const FILE_ATTRIBUTE_READONLY = 0x1, FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_DIRECTORY = 0x10, FILE_ATTRIBUTE_ARCHIVE = 0x20;

const INVALID_DOS_CHARS = '*?<>|"+=,;[] å';
function isInvalidDosChar(ch) {
  if (ch.charCodeAt(0) > 0x7f) return true;
  return (INVALID_DOS_CHARS + '~.').includes(ch);
}
const toUpper = (c) => (c >= 'a' && c <= 'z' ? String.fromCharCode(c.charCodeAt(0) - 32) : c);
const toLower = (c) => (c >= 'A' && c <= 'Z' ? String.fromCharCode(c.charCodeAt(0) + 32) : c);

/** Wine is_legal_8dot3_name */
function isLegal8dot3(name) {
  const len = name.length;
  if (len > 12) return false;
  if (len > 0 && name[0] === '.') return len === 1 || (len === 2 && name[1] === '.');
  let dot = -1;
  for (let i = 0; i < len; i++) {
    const c = name[i];
    if (c.charCodeAt(0) > 0x7f) return false;
    if ((INVALID_DOS_CHARS + '~').includes(c)) return false;
    if (c === '.') { if (dot !== -1) return false; dot = i; }
  }
  if (dot === -1) return len <= 8;
  if (dot > 8) return false;
  return len - dot > 1 && len - dot < 5;
}

/** Wine hash_short_file_name (case-insensitive variant). */
function hashShortName(name) {
  const hashChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
  const end = name.length;
  let hash = 0xbeef;
  let p = 0;
  const lc = (i) => toLower(name[i]).charCodeAt(0);
  for (; p < end - 1; p++) hash = ((hash << 3) ^ (hash >> 5) ^ lc(p) ^ (lc(p + 1) << 8)) & 0xffff;
  hash = ((hash << 3) ^ (hash >> 5) ^ lc(p)) & 0xffff;
  let ext = -1;
  for (p = 1; p < end - 1; p++) if (name[p] === '.') ext = p;
  let out = '';
  let i = 4;
  for (p = 0; i > 0; i--, p++) {
    if (p === end || p === ext) break;
    out += isInvalidDosChar(name[p]) ? '_' : toUpper(name[p]);
  }
  while (i-- >= 0) out += '~';
  out += hashChars[(hash >> 10) & 0x1f] + hashChars[(hash >> 5) & 0x1f] + hashChars[hash & 0x1f];
  if (ext >= 0) {
    out += '.';
    let k = 3;
    for (let e = ext + 1; k > 0 && e < end; k--, e++) out += isInvalidDosChar(name[e]) ? '_' : toUpper(name[e]);
  }
  return out;
}

/** Wine match_filename (case-insensitive). */
function matchMask(name, mask) {
  let n = 0, m = 0;
  const ne = name.length, me = mask.length;
  let lastjoker = -1, nextToRetry = -1;
  const up = (s, i) => toUpper(s[i]);
  while (n < ne && m < me) {
    const c = mask[m];
    if (c === '*') {
      m++;
      while (m < me && mask[m] === '*') m++;
      if (m === me) return true;
      lastjoker = m;
      while (n < ne && up(name, n) !== up(mask, m)) n++;
      nextToRetry = n;
    } else if (c === '?') {
      m++; n++;
    } else if (up(mask, m) === up(name, n)) {
      m++; n++;
      if (m === me) {
        if (n === ne) return true;
        if (lastjoker >= 0) m = lastjoker;
      }
    } else {
      if (lastjoker < 0) return false;
      m = lastjoker;
      nextToRetry++;
      n = nextToRetry;
    }
  }
  while (m < me && (mask[m] === '.' || mask[m] === '*')) m++;
  return n === ne && m === me;
}

const hasWildcard = (mask) => /[*?]/.test(mask);

/** rcthook.c cd_alias(): first five characters other than ' ' and '.', upper-cased, then "~1". */
function cdAlias(longName, alt) {
  if (!alt) return alt;
  let a = '';
  for (const ch of longName) {
    if (a.length >= 5) break;
    if (ch === ' ' || ch === '.') continue;
    a += toUpper(ch);
  }
  return a + '~1';
}

/**
 * Build the entry list the hook hands out. `listing` is [{name, isDir, size, writable}] (the
 * directory's entries, with "." and ".." if the directory has them), `mask` the last path
 * component, `onCd` whether the pattern starts with D:.
 */
function buildFindSet(listing, mask, onCd) {
  const out = [];
  const wild = hasWildcard(mask);
  for (const e of listing) {
    const legal = isLegal8dot3(e.name);
    const shortName = legal ? '' : hashShortName(e.name);
    if (wild) {
      if (!matchMask(e.name, mask) && !(shortName && matchMask(shortName, mask))) continue;
    } else if (toUpper2(e.name) !== toUpper2(mask) && !(shortName && toUpper2(shortName) === toUpper2(mask))) continue;
    let attr = e.isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (!e.writable) attr |= FILE_ATTRIBUTE_READONLY;
    if (e.name[0] === '.' && e.name !== '.' && e.name !== '..') attr |= FILE_ATTRIBUTE_HIDDEN;
    out.push({ attr, sizeLow: e.isDir ? 0 : e.size >>> 0, sizeHigh: e.isDir ? 0 : Math.floor(e.size / 4294967296), name: e.name, alt: shortName });
  }
  out.sort((a, b) => cmpBytes(a.name, b.name));
  if (onCd) for (const e of out) e.alt = cdAlias(e.name, e.alt);
  return out;
}
function toUpper2(s) { let r = ''; for (const c of s) r += toUpper(c); return r; }
function cmpBytes(a, b) {
  const x = Buffer.from(a, 'latin1'), y = Buffer.from(b, 'latin1');
  return Buffer.compare(x, y);
}

/** put_find(): store one entry into a WIN32_FIND_DATAA at guest address `p` via `w` writers. */
function putFind(mem, p, e) {
  mem.w32(p + 0, e.attr);
  for (const off of [4, 12, 20]) { mem.w32(p + off, FIND_TIME_LO); mem.w32(p + off + 4, FIND_TIME_HI); }
  mem.w32(p + 28, e.sizeHigh);
  mem.w32(p + 32, e.sizeLow);
  mem.w32(p + 36, 0);
  mem.w32(p + 40, 0);
  mem.wstr(p + 44, e.name);
  mem.wstr(p + 304, e.alt);
}

module.exports = {
  isLegal8dot3, hashShortName, matchMask, hasWildcard, cdAlias, buildFindSet, putFind,
  FIND_TIME_LO, FIND_TIME_HI, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY,
};
