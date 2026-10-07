#!/usr/bin/env node
'use strict';
// Run the lifted rct.exe.
//
//   node lift/run.js --exe <rct.exe> --game <dir> --script <s> --out <dir> [--lift out/lift]
//                    [--instrument] [--no-host]
//
// The host (lift/host/index.js) is attached through one function:
//   attach(m, {exePath, gameDir, scriptPath, outDir, rt}) -> host
// where host may have finish({exit?, error?}) -> exit status (number), called once at the end.
// Without a host (or --no-host) every import is unbound and the run stops at the first host
// call with HostMissing, naming it.

const fs = require('fs');
const path = require('path');
const rt = require('./runtime');

function parseArgs(argv) {
  const o = { lift: path.join(__dirname, '../out/lift') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--exe') o.exe = val();
    else if (a === '--game') o.game = val();
    else if (a === '--script') o.script = val();
    else if (a === '--out') o.out = val();
    else if (a === '--lift') o.lift = val();
    else if (a === '--instrument') o.instrument = true;
    else if (a === '--no-host') o.noHost = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.exe) throw new Error('--exe is required');
  return o;
}

function describeState(m) {
  const r = m.regs();
  const h = (v) => rt.hex(v);
  return `eip=${h(r.eip)} eax=${h(r.eax)} ebx=${h(r.ebx)} ecx=${h(r.ecx)} edx=${h(r.edx)} ` +
    `esi=${h(r.esi)} edi=${h(r.edi)} ebp=${h(r.ebp)} esp=${h(r.esp)} eflags=${h(r.eflags)} depth=${m.depth}`;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.out) fs.mkdirSync(o.out, { recursive: true });
  const t0 = process.hrtime.bigint();
  const m = rt.createMachine({ exePath: o.exe, liftDir: o.lift });
  const tLoad = Number(process.hrtime.bigint() - t0) / 1e9;
  if (o.instrument) m.enableInstrumentation();
  let host = null;
  const hostIndex = path.join(__dirname, 'host', 'index.js');
  if (!o.noHost && fs.existsSync(hostIndex)) {
    host = require(hostIndex).attach(m, { exePath: o.exe, gameDir: o.game, scriptPath: o.script, outDir: o.out, rt });
  }
  let status = 0, result = {};
  const t1 = process.hrtime.bigint();
  try {
    m.run();
    result = { error: new Error('top-level run returned (HOST_RETURN at depth 0)') };
  } catch (e) {
    result = e instanceof rt.GuestExit ? { exit: e.code } : { error: e };
  }
  const secs = Number(process.hrtime.bigint() - t1) / 1e9;
  if (result.error) {
    const e = result.error;
    process.stderr.write(`lift run stopped: ${e.message}\n  ${describeState(m)}\n`);
    if (!(e instanceof rt.MissingBlock || e instanceof rt.HostMissing || e instanceof rt.GuestFault ||
      e instanceof rt.GuestException)) process.stderr.write(e.stack + '\n');
    status = 1;
  }
  if (host && host.finish) {
    const s = host.finish(result);
    if (typeof s === 'number') status = s;
  }
  const stats = { load_s: tLoad, run_s: secs, host_calls: m.hostCalls };
  if (o.instrument) Object.assign(stats, { blocks: m.blockCount, insns: m.insnCount, insns_per_s: Math.round(m.insnCount / secs) });
  process.stderr.write(`lift run: ${JSON.stringify(stats)}${result.exit !== undefined ? ' exit=' + result.exit : ''}\n`);
  if (o.out) fs.writeFileSync(path.join(o.out, 'lift-run.json'), JSON.stringify({ ...stats, exit: result.exit, error: result.error ? result.error.message : undefined }, null, 1));
  process.exitCode = status;
}

main();
