# Rezig status

## Current phase

P0 complete: clean extraction, whole-image measurement, and a 50-function differential slice.

## Done

- Repository scaffold, Zig 0.17.0 pinned.
- CLI parsing (`extract`, `analyze`, `xex`, `codegen`, `build`, `run`, `help`).
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
- Projected 24,000 functions: about 24 s, 4 GB RSS, 400 MB object, if scaling stays linear.
- Chunked compilation is therefore viable. The limit today is coverage, not compiler cost:
  call-closed selection tops out near 1,200 functions because call targets must be emittable too.

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
- coverage, now seeded from `.pdata`: 24,513 function starts, 28,038 discovered functions,
  1,800,711 unique instructions = 76.73% of `.text` (2,346,754 words). 83.77% of instruction
  instances decode and emit, 2,915 functions are fully emittable. Integer, single-precision
  float, branches, calls, tail calls and the five decoded VMX ops (`vor`, `vxor`, `vaddfp`,
  `lvx`, `stvx`) are lowered. The remaining limit is decoding: 581,975 instruction instances,
  mostly primary opcodes 31, 62, 04, 58 and 40. `coverage` now prints the top
  undecoded forms by primary opcode and extension field, with a sample word. Reproduce with
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

## Remaining for P0

- Guest-truth traces, if wanted.
- `build.zig` still has near-duplicate step helpers.

## Next

P1: float/VMX, out-of-function `b` (tail calls), then the undecoded primary opcodes and
whole-image emission. Branches, loops, conditional returns and direct calls are done.
