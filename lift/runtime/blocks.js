'use strict';
// Loads the lifter's output (out/lift/manifest.json + blocks-*.js) into a machine's block table.

const fs = require('fs');
const path = require('path');
const C = require('./constants');

const IMAGE_SPAN = C.IMAGE_HI - C.IMAGE_LO;

function newBlockTable() {
  // A packed array (not `new Array(n)`, which V8 keeps in slow dictionary mode for large n).
  const t = [];
  for (let i = 0; i < IMAGE_SPAN; i++) t.push(undefined);
  return t;
}

// Install generated blocks from `dir` into machine `m`. Returns the manifest.
function loadBlocks(m, dir, { expectMd5, noRegions = !!process.env.LIFT_NO_REGIONS } = {}) {
  const man = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  if (expectMd5 && man.binary_md5 !== expectMd5) throw new Error(`lift in ${dir} was generated from a different rct.exe`);
  const rt = require('./ops');
  m.blocks = newBlockTable();
  m.blockInsns = new Uint16Array(IMAGE_SPAN);
  let n = 0;
  const def = (addr, ninsn, fn) => {
    const i = addr - C.IMAGE_LO;
    m.blocks[i] = fn; m.blockInsns[i] = ninsn; n++;
  };
  for (const f of man.files) require(path.resolve(dir, f))(rt, def);
  if (n !== man.nblocks) throw new Error(`loaded ${n} blocks, manifest says ${man.nblocks}`);
  // m.blocksFine: one function per block (instrumented loop, capture). m.blocks: the dispatch
  // table of the plain loop: region functions where the lift has them.
  m.blocksFine = m.blocks;
  if (man.regions && man.regions.files && man.regions.files.length && !noRegions) {
    m.blocks = m.blocksFine.slice();
    let nr = 0;
    const defr = (starts, factory) => {
      nr++;
      const base = starts[0], X = new Int16Array(starts[starts.length - 1] - base + 1).fill(-1);
      starts.forEach((a, k) => { X[a - base] = k; });
      const fn = factory(X);
      for (const a of starts) m.blocks[a - C.IMAGE_LO] = fn;
    };
    for (const f of man.regions.files) require(path.resolve(dir, f))(rt, defr);
    if (nr !== man.regions.count) throw new Error(`loaded ${nr} regions, manifest says ${man.regions.count}`);
    m.hookable = new Set(man.hooks.map((x) => Number(x)));
  }
  m.liftManifest = man;
  return man;
}

// For tests: install hand-written blocks {addr: fn} (fn(m) -> next eip).
function installBlocks(m, table) {
  if (!m.blocks) { m.blocks = newBlockTable(); m.blockInsns = new Uint16Array(IMAGE_SPAN); m.blocksFine = m.blocks; }
  for (const [a, fn] of Object.entries(table)) { const i = Number(a) - C.IMAGE_LO; m.blocks[i] = fn; m.blocksFine[i] = fn; m.blockInsns[i] = 1; }
}

module.exports = { loadBlocks, installBlocks, newBlockTable };
