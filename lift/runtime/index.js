'use strict';
// Public entry point of the lift runtime. See README.md in this directory.

const C = require('./constants');
const M = require('./memory');
const { Machine, MissingBlock, HostMissing, GuestException, GuestExit } = require('./machine');
const { loadImage, EXPECTED_MD5 } = require('./loader');
const { loadBlocks, installBlocks } = require('./blocks');

// Create the (single) guest machine: reset memory, load rct.exe, load lifted blocks,
// prepare the main thread at the entry point. Guest memory is a process-wide singleton, so
// there is one machine per Node process.
function createMachine({ exePath, liftDir, checkMd5 = true } = {}) {
  M.resetMemory();
  const m = new Machine();
  const img = loadImage(exePath, { checkMd5 });
  m.installImports(img.imports);
  m.image = img;
  if (liftDir) loadBlocks(m, liftDir, { expectMd5: checkMd5 ? EXPECTED_MD5 : undefined });
  m.initThread(img.entry);
  return m;
}

module.exports = {
  ...C, ...M,
  Machine, MissingBlock, HostMissing, GuestException, GuestExit,
  loadImage, loadBlocks, installBlocks, createMachine,
};
