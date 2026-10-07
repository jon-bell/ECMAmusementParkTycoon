'use strict';
// Entry point of the host for lift/run.js (interface agreed in out/status/lifter.md):
//   const host = require('./host').attach(m, {exePath, gameDir, cdDir, scriptPath, outDir, rt});
//   try { m.run(); } catch (e) { ... } ; process.exitCode = host.finish({exit, error});
// Exit status as the oracle's (oracle/README.md): 0 the script reached quit, 3 the script is
// malformed or unreadable, 4 a modal dialog, other values: the run ended otherwise.
const { Host, HostNotImplemented, HostDialog, HostQuit } = require('./host');

function attach(m, o) {
  const h = new Host(m, o);
  h.install();
  return h;
}

module.exports = { attach, Host, HostNotImplemented, HostDialog, HostQuit };
