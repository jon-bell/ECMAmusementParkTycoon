# Lift runtime

The machine that runs the lifted `rct.exe`: guest memory, PE loader, registers and flags,
dispatcher, host-call ABI and guest calls. It implements the execution model of
`docs/stage1-design.md`; this file is the interface the host (`lift/host/`) binds against.
Node 18 (`/usr/bin/nodejs`), CommonJS, standard library only.

```js
const rt = require('./lift/runtime');
const m = rt.createMachine({ exePath: 'game/cd/English/rct.exe', liftDir: 'out/lift' });
m.bindImport('KERNEL32.dll!GetVersion', (m) => { m.eax = 0xC0000A04; m.retStd(0); });
m.hooks.set(0x4385D8, (m) => { frames++; });
try { m.run(); } catch (e) { if (!(e instanceof rt.GuestExit)) throw e; }
```

## Guest memory (`memory.js`)

- One `Uint8Array` `rt.mem` of `MEM_SIZE = 0x05400000` bytes (guest addresses
  `[0, MEM_SIZE)`), little-endian, plus `rt.dv` (a `DataView` over it).
- **Page map.** Every 4 KiB page has protection bits: `PROT_R = 1`, `PROT_W = 2`,
  `PROT_CODE = 4`. A guest access to a page without the needed bit throws `rt.GuestFault`
  (`op`, `addr`, `size`, `why`, and `blockEip` = start of the block that faulted). This is a
  refinement of the design's "outside `[0, MEM_SIZE)` faults": unmapped pages fault too, as
  on Windows, which catches wild pointers at the first access.
  - The loader maps the image (headers, `.rdata`, `.rsrc` read-only; `.data`, `DATASEG`,
    `DataSeg` read-write; `.text`, `CODESEG`, `CodeSeg` read-only + code). A guest write into a
    code section is a hard fault ("self-modifying code is not supported"), including the
    writable `CodeSeg` (the scope study found no such write, M3).
  - `initThread` maps the stack `[0x230000, 0x330000)` and the TEB page read-write.
  - The first 64 KiB are never mapped (null pointers fault).
  - **The host must map what it hands out:** `rt.mapPages(addr, size, prot)` for its heap
    arena (`0x00A00000–0x01990000`), the DIB (`0x019A0000`), the CSG1.DAT view (`0x03C80000`,
    `PROT_R`), `VirtualAlloc` regions, COM objects and vtables. `rt.unmapPages`, `rt.protOf`.
- Guest accessors (checked): `r8 r16 r32 w8 w16 w32 rf64 wf64` (addresses are uint32).
- Host conveniences (unchecked, no page map): `rt.mem`, `rt.dv`, `readBytes(a,n)`,
  `writeBytes(a,bytes)`, `readCString(a)`, `writeCString(a,s)`, `readWString(a)`.
- Memory is a process-wide singleton: one machine per Node process.

## Loader (`loader.js`)

`createMachine` loads the user's `rct.exe` (md5 checked: `59e88bbcf3a6db7ea81c648a4afba935`)
at its preferred base `0x400000`: headers + sections at their RVAs, tails zero. Every IAT slot
gets `HOST_BASE + 16*i`, `HOST_BASE = 0xFFF00000`, with `i` the import index in
import-descriptor order then thunk order (USER32 first). The list is `m.imports`:

```js
{ index, dll: 'USER32.dll', name: 'GetParent', ordinal: null,
  key: 'USER32.DLL!GetParent', iat: 0x5E7228, addr: 0xFFF00000 }
```

207 imports; two are by ordinal (`DPLAYX.DLL!#1`, `DPLAYX.DLL!#2`). `m.importByKey` maps keys
(DLL upper-cased) to entries. `m.image` has `{entry, imports, sections, md5, header}`.

## Registers and flags (`machine.js`)

`m.eax m.ecx m.edx m.ebx m.esp m.ebp m.esi m.edi m.eip`: uint32 numbers (always write `v >>> 0`).
Flags are separate 0/1 fields: `m.cf m.pf m.af m.zf m.sf m.tf m.df m.of`.
`m.getEflags()` / `m.setEflags(v)`: bit 1 always set, IF (bit 9) reads as 1, other bits 0.
`m.regs()` returns `{eax..edi, esp, ebp, eip, eflags}`; `m.setRegs(obj)`.

`m.fsBase` is the `fs:` segment base (`TEB_BASE = 0x00380000`); all other segments are flat.
`initThread` writes a minimal TEB: `[+0]` ExceptionList = `0xFFFFFFFF`, `[+4]` StackBase
`0x330000`, `[+8]` StackLimit `0x230000`, `[+0x18]` Self. The C runtime only uses `fs:[0]`
(SEH chain; 9 instructions in `.text`). The host may fill more (PEB at `+0x30`, ...) or move
the TEB by mapping a page and setting `m.fsBase`.

x87 state: `m.fpu = {st: Float64Array(8), top, tag, cw: 0x027F, sw}` (see `ops.js`).

## Dispatch

`m.blocks[eip - IMAGE_LO]` holds one function per lifted basic block (`fn(m) -> next eip`).
`m.run()` runs from `m.eip`:

1. if a hook is registered at `eip`, call it first (`m.eip === eip`). It may do anything,
   including guest calls. Returning a number redirects to that eip (hooks are checked again at
   the new address); returning `undefined` executes the block.
2. run the block at `eip`. `m.eip` is kept current only where host code can observe it: in
   hooks, host functions, `onBlock`, at `HOST_RETURN`, and when an exception leaves the loop
   (`GuestFault`: `m.eip` = `e.blockEip` = start of the faulting block; `GuestException`: the
   faulting instruction). Not updating it per block avoids a V8 deoptimisation on every host call;
3. no block: `eip === HOST_RETURN` ends this `run()` level; otherwise `m.special(eip)`:
   - `m.specials.get(eip)` if present: `fn(m) -> next eip` (markers such as
     `HOST_RETURN_LOAD`, continuations; `HOST_EXIT` is preset and throws `GuestExit(eax)`);
   - a host address `HOST_BASE + 16*k`: calls `m.hostTable[k](m)` (see below);
     unbound → `rt.HostMissing` (names the import);
   - otherwise `rt.MissingBlock(eip)`. Never ignored: it means the code map lacks a block.
     Record it; the map is extended with seeds (`tools/rctcfg.py`), not guessed at run time.

`m.hooks` is a `Map<eip, fn(m)>`. `set` refuses addresses that are not forced block starts of
the loaded lift: those listed in `lift/hooks.json` (RNG store `0x5DF42A`, tick `0x43888E`,
frame entry `0x4385D8`, frame body `0x4386EC`, `game_do_command` `0x426F56`, and `0x43054E`).
(With a lift without regions, any block start is accepted.)

**Regions.** The default lift also groups the blocks of each 128-byte code window (at most 100
instructions) into one *region* function `fn(m, eip)` that runs a `switch` loop over its blocks
and returns the first eip outside the region. `m.blocks` (the plain loop's table) maps every
block start to its region function; hook addresses are never inside a region, so a transition to
a hooked address always comes back to the dispatcher. `m.blocksFine` keeps one function per block;
the instrumented loop (coverage, `onBlock`, register capture) uses it, so instrumentation stays
per block. `LIFT_NO_REGIONS=1` disables regions at load time; `lifter.py --region-bits 0` does not
emit them. Inside a region `m._blk` tracks the current block (for `GuestFault.blockEip`).

Markers: `HOST_RETURN = 0xFFFFFFF0`, `HOST_RETURN_LOAD = 0xFFFFFFE0`, `HOST_EXIT = 0xFFFFFFD0`
(return address of the entry point). Host slots are `0 ≤ k < 0xFFFD`.

## Host-call ABI

When `eip` is a host address, the runtime calls `impl(m)` with `esp` pointing at the return
address and `m.eip` = the host address.

- `m.arg(i)` = `r32(esp + 4 + 4*i)`;
- the impl sets `m.eax` (and `m.edx` if needed);
- it returns with `m.retStd(nargs)` (pop return address into `eip`, then pop `nargs` dwords)
  or `m.retCdecl()`. An impl that returns without setting `m.eip` is an error.
- Flags after a host call are whatever the impl leaves (unspecified, as on Windows).

`m.bindImport('DLL!name', impl)` binds an import (DLL name case-insensitive) and returns its
address. `m.allocHost(name, impl)` allocates a new host address (COM methods, `GetProcAddress`
results); build COM vtables in mapped guest memory from these addresses.
`m.hostName(addr)`, `m.hostCalls` (count).

Stack helpers: `m.push32 m.pop32 m.push16 m.pop16` (checked accesses).

## Guest calls from the host

`m.callGuest(addr, regs?)` sets the given registers (`eax..edi`, `ebp`, `esp`, `eflags`),
pushes `HOST_RETURN`, runs a nested dispatch loop until `eip === HOST_RETURN`, restores
`m.eip` to its value before the call (e.g. the host address of the import being executed)
and returns `m.regs()`. It saves nothing else: the host saves and restores what it must. For a
stdcall callback, push the arguments (last first) before calling; the callee's `ret n` pops
them. Nesting is unlimited (`m.depth`).

Caveat: a guest long-jump that unwinds past a nested `callGuest` (e.g. the main-loop longjmp
`mov esp,[0x991F6C]; jmp 0x438A1D` inside a window procedure) leaves that nested JS loop
running the main loop. That is correct guest behaviour but costs one JS stack level per
occurrence. The `load` action must not use `callGuest` for this reason (design: push
`HOST_RETURN_LOAD`, redirect from the frame-body hook).

## Exceptions

- `rt.GuestFault`: guest memory access fault (not restartable; `blockEip` set).
- `rt.GuestException(kind, eip)`: CPU exception raised by an instruction: `'DE'` (div/idiv by
  zero or quotient overflow), `'BP'` (`int3`). `m.eip` is the faulting instruction and every
  register and flag holds its value from before that instruction. If `m.onException(m, e)` is
  set, the dispatcher calls it and resumes at the eip it returns (the host builds the Win32
  exception dispatch: `EXCEPTION_INT_DIVIDE_BY_ZERO` etc.); otherwise it propagates.
- `rt.GuestExit(code)`: end of the process (throw it from `ExitProcess`).
- `rt.MissingBlock`, `rt.HostMissing`: see above.

## Thread start

`initThread(entry)` (called by `createMachine`): maps stack and TEB, zeroes `eax..edi`,
`ebp`, `eflags = 0x202`, `esp = 0x0032FF00 - 4` with `[esp] = HOST_EXIT`, `eip = 0x412E80`.
The host may overwrite any of this (e.g. initial register values seen in the oracle's API
trace) before `m.run()`.

## Instrumentation

`m.enableInstrumentation({coverage})` switches to the instrumented loop: `m.blockCount`,
`m.insnCount` (static instruction counts per block), `m.coverage` (`Uint8Array` over the
image, 1 = block executed), and `m.onBlock(m, eip)` before every block (register capture).

## Register capture

`require('./capture').start(m, file, {mapBlocks})` writes the lift-side stream of
`oracle/README.md` ("Register capture"): `R` at every block entry (registers before the block,
`eflags = getEflags()`), `W` for every guest store, `O` at every host-function dispatch
(`m.xslot` = the `[disp32]` slot of the indirect call/jmp, else 0; return address), and `T`
records from `cap.tick(n)`. Starting it switches the dispatcher to the instrumented loop (also
from inside a hook); `cap.stop()` restores the previous mode. Use a lift built with
`--no-flag-opt` (`out/lift-ref`): the optimised lift leaves dead flags stale at block entries.

## Lifted code

`out/lift/` (git-ignored, derived from the user's binary) holds `manifest.json` and
`blocks-*.js`, generated by `lift/lifter.py`; `loadBlocks(m, dir)` installs them. For tests,
`rt.installBlocks(m, {addr: fn})` installs hand-written blocks.
