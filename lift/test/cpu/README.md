# CPU differential tests

The lifted instruction semantics against the host CPU. Wine runs 32-bit code natively, so the
oracle machine's own CPU (the CPU the oracle runs on) executes each test instruction.

```
lift/test/cpu/build.sh                                   # out/cpu/harness.exe + Wine prefix out/cpu/prefix
.venv/bin/python lift/lifter.py --single --out out/lift-single
.venv/bin/python lift/test/cpu/cpudiff.py gen --set map --per 4 --out out/cpu/full
.venv/bin/python lift/test/cpu/cpudiff.py run --dir out/cpu/full --jobs 8
/usr/bin/nodejs lift/test/cpu/compare.js out/cpu/full out/lift-single --json out/cpu/full/diff.json

.venv/bin/python lift/test/cpu/cpudiff.py gen --set synth --per 60 --out out/cpu/syn
.venv/bin/python lift/test/cpu/cpudiff.py run --dir out/cpu/syn
.venv/bin/python lift/lifter.py --insns out/cpu/syn/synth.json --out out/lift-synth
/usr/bin/nodejs lift/test/cpu/compare.js out/cpu/syn out/lift-synth
.venv/bin/python lift/test/cpu/flagfit.py out/cpu/syn      # fit SDM-undefined flags (HW model)
```

## What a test is

One instruction, one input state:

- `--set map`: every instruction start of the code map, at its own address in a copy of the
  user's rct.exe image (IAT filled with the lift's host addresses), so absolute addresses, jump
  tables and relative branches are the real ones.
- `--set synth`: hand-encoded instructions at 0x02800000+ covering forms and operand values the
  map does not (every shift/rotate count 0..33 plus masked counts, every ALU op at 8/16/32 bits
  and high bytes, mul/div at every width, bt/bts/btr/btc, bsf, setcc and jcc on all 16
  conditions, loop/jcxz with and without 0x67, string instructions with DF and overlap).
- Registers random (special values mixed in); flags random; base/index registers solved so every
  memory operand lands in scratch memory (0x02000000, stack scratch 0x02100000-0x02400000) or, for
  `[reg + table]` forms, inside the real table; string instructions get small counts, random DF and
  overlapping ranges; `bt` with a register offset gets offsets in [-300, 300]; instructions that
  write esp get stack values so the harness survives. Memory regions around every access are
  filled with random bytes (read-only image sections keep their contents).

## The native side (harness.c)

`harness.exe` is linked at 0x400000 with an uninitialised section covering rct.exe's image span
(so Wine cannot place its own allocations there), copies the image in, and applies the lift's
page protections (code read-only, CodeSeg read-only). Each test loads all registers and EFLAGS
with TF set through `iretd` to the instruction, which executes exactly once (REP instructions:
until done) and traps; a vectored handler captures the CONTEXT and resumes the harness.

## Comparison (compare.js)

The lift side sets the same state (including the 12-byte IRET frame below esp), runs the
lifted instruction and compares: registers, eip, CF PF AF ZF SF OF DF, memory regions (bytes of
the stack scratch below the final esp are skipped: Wine builds its exception frame there).
Native access violation -> the lift must raise GuestFault; native #DE -> GuestException DE with
every register unchanged. Not natively testable here: x87, cpuid, int3 and `fs:` instructions
(26 in the map; covered by `lift/test/semantics.test.js`). 16-bit `pushf`/`popf` crash Wine's
trap handling (misaligned esp / popped NT) and are reported as native crashes.

## File formats

`tests.bin`: `"CPT1"`, u32 count, then per test: u32 addr, u32 flags (bit 0 REP), u32 eax ecx
edx ebx esp ebp esi edi, u32 eflags, u32 ncode + code bytes (padded to 4), u32 nregions, then per
region u32 addr, u32 len, u32 flags (bit 0 read-only: not written) + bytes (padded to 4).
`results.bin`: u32 magic `"CPR1"`, u32 count, u32 cs, u32 0, then per test: u32 exception code
(0x80000004 single step, 0xC0000005 AV, 0xC0000094 #DE, 0xFFFFFFFF native crash), u32 fault
address, u32 eax ecx edx ebx esp ebp esi edi, u32 eip, u32 eflags, then each region's bytes
after the instruction (padded to 4). Everything under out/ (derived from the user's binary).
