# Rezig status

## Current phase

P0 pipeline complete: clean extraction, whole-image measurement, and a 50-function differential slice. Boot is early.

## Done

- Repository scaffold, Zig 0.17.0 pinned.
- CLI parsing (`extract`, `analyze`, `coverage`, `imports`, `xex`, `codegen`, `help`), with `--elf` input for analyze/coverage/codegen.
- XDVDFS reader, XEX2 header parser, AES-128-CBC, XEX image decrypt + basic decompress + PE parse.
- `zig build extract` and `zig build analyze`.
- Key resolution: `--key`, then `REZIG_XEX_KEY`, then `~/.config/rezig/xex.key`. No key ships
  in this repo, and `analyze --xex <file>` works on an already-unlocked XEX with no key at all.

## Real ISO gate (2026-10-30)

GTA IV USA disc 1.0, no title update:

- `zig build extract -Diso=<usa.iso> -Dout=data/gta4`:
  `extracted 170 files, 6956031956 bytes, skipped 0` in 1m18s.
- Second run: `extracted 170 files, 0 bytes, skipped 170` in 26s.
- `default.xex` version `0.0.0.5`.
- `rezig analyze --tree data/gta4` with no key: prints the four ways to supply a key or an
  unlocked XEX, exit 1. With the 32-byte RPF key: `BadKeySize ... is 32 bytes, expected 16`.
- 11eyes CrossOver (Japan): parsed read-only as 443 files / 5,103,914,123 bytes. Not extracted
  because `/home` had 5.0 GB free at the time; the reader accepted its volume descriptor.
- Disk image facts: game partition at `0xFD90000`; directory links are 4-byte-unit offsets with
  `0` meaning none; the field at volume offset `0x1C` is not an image size, so entry bounds come
  from the source file size.

## Unlocked image gate (2026-10-30)

First produced offline with XexTool 7.0. Now `rezig xex` produces the same bytes in-process:

```
zig build xex -Dxex=data/gta4/default.xex -Dout=<unlocked.xex> -Dkey=<key>
cmp <unlocked.xex> data/gta4/default.xex.unenc
zig build analyze -Dxex=<unlocked.xex>
```

Output: version `0.0.0.5`, title `545407F2`, base `0x82000000`, entry `0x829A0860`,
image `0x011F0000`, 13 PE sections. `.text` rva `0x120000` size `0x008E32AC`; bytes there start
`7d8802a6` (`mflr r12`), so the payload is a memory image indexed by RVA.

Two facts this exposed:

- `SizeOfImage` (`0x135B000`) is larger than the stored payload (`0x11F0000`) and some sections
  extend past it; the tail is zero-filled at load. Loader checks relaxed accordingly.
- XexTool's `-e u` decrypts but keeps basic compression; `-c u` does not rewrite the block table.
  Our loader handles that combination.

## Blocked

- Guest truth: no Xenia or Unicorn traces exist in the repo, so the differential proves lowering,
  not PPC semantics.

## Whole-image budget

- 1,000 emitted functions: 1.0 s to compile, 163 MB peak RSS, 16.8 MB Debug object.
- A single 82.3 MB file does not compile: the compiler misreports type errors past roughly
  2,000 functions, so `codegen --all` emits chunks of ~1,000 functions plus a central
  `dispatch.zig`.
- All 24,538 supported functions compile and link in 25 chunks.
- The chunked build caught six emitter bugs the 50-function gate could not: two missing
  parentheses, `mulli`/`extsh`/`extsb`/`extsw` sign conversions, an `&`-vs-`+%` precedence fault
  in every address computation, and a 64-bit carry in `stwu` updates.
- Call-closed selection tops out near 1,200 functions because call targets must be emittable too.

## Boot trace

`zig build boot -Dxex=<xex> [-Dkey=<key>]` builds the whole image and runs the XEX entry point
against stub imports. Each import is logged once. The current trace reaches seventeen imports
and then branches to address zero:

```
import xboxkrnl.exe[0x125] ... import xboxkrnl.exe[0x130] ...
import xboxkrnl.exe[0x194] ... import xam.xex[0x3CB] ...
import xboxkrnl.exe[0x10]  ... import xboxkrnl.exe[0x152] ...
import xboxkrnl.exe[0x155] ... import xam.xex[0x282] ...
import xam.xex[0x33]       ... import xam.xex[0x2] ...
import xboxkrnl.exe[0xD1]  ... import xboxkrnl.exe[0x110] ...
import xam.xex[0x3D1]      ... import xboxkrnl.exe[0x52] ...
import xboxkrnl.exe[0x154] ... import xboxkrnl.exe[0x3] ...
import xam.xex[0x1A9]
boot: fault unsupported at 0x0
```

Most stubs still return without setting `r3`. The next step is real kernel behaviour: memory,
threads and the XAM calls that return pointers or handles.

## Homebrew targets (2026-10-31)

Two homebrew images were tested outside the repository.

Better16, XEX, devkit/debug key:

- base `0x82000000`, entry `0x83254308`, image `0x1880000`, `.text` rva `0x7A0000` size `0xE0546C`.
- The execution-info optional header is absent; rezig now accepts that and reports version/title zero.
- coverage: 92,090 `.pdata` starts, 100,678 functions, 3,374,972 unique instructions =
  91.82% of `.text`. R1 closed decode and emit to 100.00% of discovered code.
- boot compiles the whole image and now fails at runtime in recursive dispatch at `0x835A4A8C`.

ClassiCube, ELF32 PowerPC:

- entry `0x86200`, `.text` size `0xBBE60`, one RWX load segment, `.eh_frame_hdr` present.
- `--elf` input was added for `analyze`, `coverage` and `codegen`; boot is XEX-only.
- 3,242 FDE starts from `.eh_frame_hdr`; coverage: 8,011 functions, 176,993 unique
  instructions = 91.98% of `.text`. R1 closed decode and emit to 100.00%.
- `zig build gate -Delf=<file> -Dslice=50` passes 50 x 64 cases.

## R1 codegen completeness (2026-10-31)

Both homebrew targets now decode, emit and compile every discovered function.

Better16:

- 100,678 functions, 3,480,190 instruction instances.
- decode 100.00%, emit 100.00%, fully emittable 100,678 (100.00%).
- `codegen --all`: 100,678 functions in 101 chunks, 479 MB, about 1m54s.
- `zig build boot` compiles the whole image. The run then segfaults in recursive
  dispatch at `0x835A4A8C`; that is an R2 runtime bug, not a codegen gap.

ClassiCube:

- 8,011 functions, 612,011 instruction instances.
- decode 100.00%, emit 100.00%, fully emittable 8,011 (100.00%).
- `codegen --all`: 8,011 functions in 9 chunks, 84 MB, about 3s.

Discovery now drops `.pdata` seeds whose first word is not an instruction.
Reserved primary 0/5 words, unlisted VMX encodings and a few reserved POWER
forms lower as padding. The padding shortcut is documented in
`src/ppc/decode.zig`; replace it with CFG blocks when data-bearing functions
are verified.

## Conversion

`rezig xex` links the reader, writer, packer and LZX from the GPL Zig port of XexTool. The
library takes console keys from its caller, so rezig's binary contains no AES key constants and
no signing private key; the user's key arrives through the normal resolution order.

Verified on 2026-10-30: the rewritten `default.xex` is byte-identical to the copy the C++ tool
produced (11,841,536 bytes), and the result passes `analyze` and the 3200-case gate.

## Licence

GPL-3.0-or-later, chosen because the XEX writer comes from the GPL Zig port of XexTool.

## Toolchain notes

- `zig objdump` is a stub in 0.17.0 (`TODO dump elf file`). `llvm-objdump` (Homebrew) disassembles
  PowerPC64 objects correctly; `zig build-obj -target powerpc64-linux-gnu` assembles them. Use that
  pair to verify instruction encodings for Task 9 instead of hand-transcribing them.
- PE headers inside a XEX image are little-endian, even though guest code is big-endian.

## P0 progress

Done and verified on the real disc:

- extract: 170 files, 6,956,031,956 bytes; rerun skips all 170.
- analyze: version `0.0.0.5`, title `545407F2`, entry `0x829A0860`, 13 PE sections from
  `data/gta4/default.xex.unenc`. No key needed for that file.
- ppc decode: 44 cases, encodings assembled with Zig and confirmed with `llvm-objdump`.
- discovery: 26,590 leaf candidates in `.text`; 9,121 inside the current subset.
- codegen: 50 functions from `tests/slice/addresses.json`, `zig fmt` clean.
- coverage, now seeded from `.pdata` and following tail branches: 24,513 starts, 34,545
  discovered functions, 2,124,676 unique instructions = 90.53% of `.text` (2,346,754 words).
  95.00% of instruction instances decode, 94.94% emit, and 24,538 functions are fully
  emittable (71.03%). The remaining limit is decoding: 109,326 instruction instances,
  mostly primary opcodes 04, 05, 03 and 31. `coverage` prints the top undecoded forms by
  primary opcode and extension field, with a sample word. Reproduce with
  `zig build coverage -Dxex=<xex>`.
- gate: 50 functions x 64 seeded cases = 3200 differential cases, emitted Zig vs the interpreter,
  PASS. Compares GPR/CR/XER/LR/CTR, fault kind/addr/size and every page byte. The slice includes
  branches, loop bodies and nine `bl` call sites; call targets are pulled in by closure.
- tail calls: `b` and conditional `bc` outside the function dispatch and return to the caller.
  A synthetic interpreter test pins the semantics.
- float and VMX: emitter and interpreter agree on `fpr`/`vmx` in unit tests, but no real
  function that uses either is fully supported yet: every candidate also contains undecoded
  instructions. The gate therefore exercises them through unit and golden tests, not GTA IV
  code.
- portability: x86_64-windows and aarch64-linux objects build.
- boot: reaches seventeen imports and stops on a zero indirect target after `xam[0x1A9]`.

## Bugs the differential found

- `mtlr`/`mtctr` assigned a 64-bit register to the 32-bit LR/CTR field.
- `or`, `andi.`, `ori`, `oris` and `sraw` wrote the source register instead of the destination.
- `lbzu`, `lwzu`, `stwu` did not update the base register.
- `addis` read `r0` instead of literal zero and did not shift the immediate.
- `addi`/`addis` sign-extended to 32 bits instead of 64.
- `lbz`/`lbzu` loaded 4 bytes and reported a size-4 fault.
- Load/store immediates were emitted unsigned, turning `-4` into `+65532`.

## Limits

- The interpreter shares the decoder with the emitter, so the gate proves lowering, not decoding.
  Decoding rests on 44 instructions assembled with Zig and checked with `llvm-objdump`.
- Neither side is guest truth. That still needs an independent CPU (Xenia, or Unicorn for single
  instructions).

## Remaining

- Guest-truth traces, if wanted.
- Kernel behaviour: memory, threads, events, files, timing and the XAM surface.
- Decoder gaps: primary opcodes 04, 05, 03 and the remaining `bclr`/`bc` forms.
- GPU, audio, input and saves.

## Next

Kernel HLE: make the imports reached by the boot trace return valid pointers and handles.
Then work the next fault from the trace.
