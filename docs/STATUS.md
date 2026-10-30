# Rezig status

## Current phase

P0 — clean extraction, then a 20-function Zig slice.

## Done

- Repository scaffold, Zig 0.17.0 pinned.
- CLI parsing (`extract`, `analyze`, `codegen`, `build`, `run`, `help`).
- XDVDFS reader, XEX2 header parser, AES-128-CBC, XEX image decrypt + basic decompress + PE parse.
- `zig build extract` and `zig build analyze`.

## Real ISO gate (2026-10-30)

GTA IV USA disc 1.0, no title update:

- `zig build extract -Diso=<usa.iso> -Dout=data/gta4`:
  `extracted 170 files, 6956031956 bytes, skipped 0` in 1m18s.
- Second run: `extracted 170 files, 0 bytes, skipped 170` in 26s.
- `default.xex` version `0.0.0.5`, image not verified (no 16-byte XEX key supplied).
- `rezig analyze` with the 32-byte RPF key at `~/.local/share/LibertyRecomp/aes_key.bin`:
  `BadKeySize ... (key file is 32 bytes, expected 16)`, exit 1. Correct: that file is the RPF key.
- 11eyes CrossOver (Japan): parsed read-only as 443 files / 5,103,914,123 bytes. Not extracted
  because `/home` had 5.0 GB free at the time; the reader accepted its volume descriptor.
- Disk image facts: game partition at `0xFD90000`; directory links are 4-byte-unit offsets with
  `0` meaning none; the field at volume offset `0x1C` is not an image size, so entry bounds come
  from the source file size.

## Toolchain notes

- `zig objdump` is a stub in 0.17.0 (`TODO dump elf file`). `llvm-objdump` (Homebrew) disassembles
  PowerPC64 objects correctly; `zig build-obj -target powerpc64-linux-gnu` assembles them. Use that
  pair to verify instruction encodings for Task 9 instead of hand-transcribing them.
- PE headers inside a XEX image are little-endian, even though guest code is big-endian.

## Blocked

- 20-function gate needs a user-supplied 16-byte XEX key. Without it `analyze`, `codegen` and
  `gate` cannot decrypt the image.

## Next

Task 9: PPC instruction decode.
