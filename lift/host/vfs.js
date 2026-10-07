'use strict';
// The file system the game sees, mirroring the oracle's run prefix (scripts/oracle-run.sh):
//   C:\Program Files\Hasbro Interactive\RollerCoaster Tycoon  -> the user's pristine install
//       (game/prefix/drive_c/Program Files/Hasbro Interactive/RollerCoaster Tycoon), never
//       written; every write goes to a per-run overlay directory (copy on write), so a run sees
//       exactly what an oracle run sees in its fresh copy of the prefix;
//   D:\  -> the CD contents (game/cd), read-only;
//   the working directory is the game directory (oracle-run.sh starts rct.exe from there).
// Name lookup is case-insensitive with an exact-case match preferred, like Wine on a Unix file
// system. Anything else on C: does not exist for the game (nothing outside the game directory is
// touched in the corpus).
const fs = require('fs');
const path = require('path');

const GAME_WIN = 'C:\\Program Files\\Hasbro Interactive\\RollerCoaster Tycoon';
const GAME_PARTS = ['PROGRAM FILES', 'HASBRO INTERACTIVE', 'ROLLERCOASTER TYCOON'];
const GAME_NAMES = ['Program Files', 'Hasbro Interactive', 'RollerCoaster Tycoon'];

const up = (s) => s.replace(/[a-z]/g, (c) => c.toUpperCase());

class Vfs {
  /** @param {{gameDir:string, cdDir:string, overlayDir:string}} o host directories */
  constructor(o) {
    this.gameDir = o.gameDir;
    this.cdDir = o.cdDir;
    this.overlayDir = o.overlayDir;
    this.cwd = GAME_WIN;
    this.whiteout = new Set();    // upper-case game-relative paths deleted during the run
    // every run starts from the pristine install, as every oracle run starts from a fresh prefix
    if (this.overlayDir) { fs.rmSync(this.overlayDir, { recursive: true, force: true }); fs.mkdirSync(this.overlayDir, { recursive: true }); }
  }

  /** Normalise a Windows path to {drive, parts[]} (absolute, '.' and '..' resolved). */
  parse(p) {
    p = p.replace(/\//g, '\\');
    let drive, rest;
    if (/^[A-Za-z]:/.test(p)) {
      drive = p[0].toUpperCase();
      rest = p.slice(2);
      if (!rest.startsWith('\\')) rest = '\\' + this.parse(this.cwd).parts.join('\\') + '\\' + rest; // drive-relative: cwd is on C:
    } else if (p.startsWith('\\')) {
      drive = 'C'; rest = p;
    } else {
      const c = this.parse(this.cwd);
      drive = c.drive; rest = '\\' + c.parts.join('\\') + '\\' + p;
    }
    const parts = [];
    for (const s of rest.split('\\')) {
      if (s === '' || s === '.') continue;
      if (s === '..') { parts.pop(); continue; }
      // Win32 strips trailing dots and spaces from path components
      const t = s.replace(/[. ]+$/, '');
      parts.push(t === '' ? s : t);
    }
    return { drive, parts };
  }

  /** Host directory layers backing a directory given by its on-disk name chain. */
  _layers(drive, names) {
    if (drive === 'D') return [{ dir: path.join(this.cdDir, ...names), layer: 'cd', writable: false }];
    if (drive !== 'C' || names.length < 3) return [];
    const rel = names.slice(3);
    const ls = [];
    if (this.overlayDir) ls.push({ dir: path.join(this.overlayDir, ...rel), layer: 'overlay', writable: true });
    ls.push({ dir: path.join(this.gameDir, ...rel), layer: 'pristine', writable: false });
    return ls;
  }

  /** Raw entries of a directory (union of layers, overlay first, whiteouts removed). */
  _entries(drive, names) {
    // synthetic ancestors of the game directory
    if (drive === 'C' && names.length < 3) {
      return [{ name: GAME_NAMES[names.length], isDir: true, size: 0, host: null, layer: 'synthetic', writable: true }];
    }
    const seen = new Map();
    const out = [];
    const relKey = drive === 'C' ? names.slice(3).map(up).join('\\') : null;
    for (const L of this._layers(drive, names)) {
      let list;
      try { list = fs.readdirSync(L.dir, { withFileTypes: true }); } catch { continue; }
      for (const d of list) {
        const key = up(d.name);
        if (seen.has(key)) continue;
        if (relKey !== null && this.whiteout.has(relKey ? relKey + '\\' + key : key)) continue;
        const host = path.join(L.dir, d.name);
        let st;
        try { st = fs.statSync(host); } catch { continue; }
        const e = { name: d.name, isDir: st.isDirectory(), size: st.size, host, layer: L.layer, mode: st.mode,
          writable: (st.mode & 0o222) !== 0 };
        seen.set(key, e);
        out.push(e);
      }
    }
    return out;
  }

  /**
   * Resolve a Windows path. Returns {drive, names (on-disk), node} where node is the entry
   * ({name,isDir,size,host,layer}) or null if the last component does not exist; `parentOk` says
   * whether every directory above it exists.
   */
  resolve(p) {
    const { drive, parts } = this.parse(p);
    const names = [];
    if (parts.length === 0) {
      const root = drive === 'D' ? { name: '', isDir: true, size: 0, host: this.cdDir, layer: 'cd' }
        : drive === 'C' ? { name: '', isDir: true, size: 0, host: null, layer: 'synthetic' } : null;
      return { drive, names, node: root, parentOk: !!root, parts };
    }
    if (drive !== 'C' && drive !== 'D') return { drive, names, node: null, parentOk: false, parts };
    for (let i = 0; i < parts.length; i++) {
      const ents = this._entries(drive, names);
      const want = parts[i];
      let hit = ents.find((e) => e.name === want) || ents.find((e) => up(e.name) === up(want));
      if (!hit) {
        return { drive, names: names.concat(parts.slice(i)), node: null, parentOk: i === parts.length - 1, parts };
      }
      names.push(hit.name);
      if (i < parts.length - 1 && !hit.isDir) return { drive, names: names.concat(parts.slice(i + 1)), node: null, parentOk: false, parts };
      if (i === parts.length - 1) return { drive, names, node: hit, parentOk: true, parts };
    }
    throw new Error('unreachable');
  }

  /** Directory listing for FindFirstFile, with "." and ".." as Wine reports them. */
  list(drive, names) {
    // The oracle's run prefix is a copy of the pristine prefix that keeps mode bits, so every
    // entry reports the write permission of its host file (overlay files are always writable).
    const ents = this._entries(drive, names).map((e) => ({ name: e.name, isDir: e.isDir, size: e.size,
      writable: e.layer === 'synthetic' || e.layer === 'overlay' || e.writable }));
    const dot = { name: '.', isDir: true, size: 0, writable: true };
    const dotdot = { name: '..', isDir: true, size: 0, writable: true };
    return [dot, dotdot, ...ents];
  }

  /** Host path in the overlay for a game-directory file given its on-disk name chain. */
  overlayPath(names) {
    if (!this.overlayDir) throw new Error('vfs: no overlay directory: writes are not allowed');
    return path.join(this.overlayDir, ...names.slice(3));
  }

  /** Is this name chain inside the game directory (and so writable through the overlay)? */
  inGameDir(drive, names) {
    return drive === 'C' && names.length >= 3 && names.slice(0, 3).every((n, i) => up(n) === GAME_PARTS[i]);
  }

  /** Make sure the parent directories of names exist in the overlay. */
  ensureOverlayParents(names) {
    fs.mkdirSync(path.dirname(this.overlayPath(names)), { recursive: true });
  }

  gameKey(names) { return names.slice(3).map(up).join('\\'); }
}

module.exports = { Vfs, GAME_WIN };
