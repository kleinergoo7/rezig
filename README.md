# Rezig

A static recompiler for Xbox 360, written in Zig. It reads a disc image, decrypts the XEX,
decodes the guest PowerPC code, and emits Zig source for the guest functions plus the runtime
they execute against.

Pilot title: **Grand Theft Auto IV**, USA disc 1.0, base game, no title update.

> **Status: early research stage. Rezig does not run GTA IV today.**
> There is no kernel, GPU, audio, input or save layer. The current output is a verified slice of
> recompiled functions, not a playable game. See [What works](#what-works) and
> [What is missing](#what-is-missing).

## Why

Xbox 360 binaries are PowerPC. A static recompiler translates them ahead of time into host code,
so a preserved game can run on modern hardware without a full emulator. Rezig aims to do that in
Zig, with every Xbox 360 specific piece implemented in this repository.

The project is also a test of a stricter idea: the recompiler and its reference interpreter are
checked against each other on real guest functions, so lowering bugs surface as mismatches
instead of silent wrong code.

## Pipeline

```
ISO  ->  XDVDFS extract  ->  XEX parse + decrypt  ->  PPC decode
     ->  function discovery (.pdata + calls)  ->  Zig emitter  ->  runtime Ctx
     ->  differential gate: emitted Zig vs interpreter
```

Each stage is a `zig build` step. No shell scripts, Python or CMake are needed to build or test.

## What works

Verified on a real GTA IV USA disc 1.0:

| Part | Result |
|---|---|
| Disc extraction | 170 files, 6,956,031,956 bytes; a rerun skips all 170 |
| XEX parse | version `0.0.0.5`, entry `0x829A0860`, 13 PE sections |
| XEX rewrite | byte-identical to the reference tool's output (11,841,536 bytes) |
| Function discovery | 24,513 `.pdata` starts, 28,038 discovered functions |
| Instruction coverage | 1,800,711 unique instructions = 76.73% of `.text` |
| Decode / emit | 83.77% / 83.56% of discovered instruction instances |
| Emitter | integer, single-precision float, VMX subset, branches, loops, direct and indirect calls, tail calls |
| Differential gate | 50 functions x 64 cases = 3,200 comparisons, all pass |
| Portability | compiles for x86_64-windows and aarch64-linux |

The gate runs each emitted function and a reference interpreter on identical seeded state and
compares GPRs, FPRs, CR, XER, LR, CTR, fault kind/address/size, and every byte of a 64 KiB page.

## What is missing

- **Kernel surface.** No `xboxkrnl`/XAM HLE, no threads, events, TLS, file I/O or timing.
- **GPU.** No Xenos command processor, shader translator, textures or Vulkan backend.
- **Audio, input, saves.** None.
- **VMX/AltiVec breadth.** Only `vor`, `vxor`, `vaddfp`, `lvx` and `stvx` are decoded and
  emitted; the rest of the vector ISA is missing.
- **Decoder gaps.** 581,975 instruction instances, mostly primary opcodes 31, 62, 04, 58, 40.
- **Whole-image emission.** The call-closed slice tops out near 1,200 functions today.
- **Indirect branches.** `bctr` and non-return `bclr` are not lowered.

`docs/STATUS.md` records the detailed numbers, known bugs and limits.

## Requirements

- Zig **0.17.0**.
- A legal copy of the Xbox 360 disc, if you want to use the real-data steps.
- A 16-byte XEX key of your own for encrypted images. An already-unlocked XEX also works for
  `analyze` and `codegen`.

rezig ships no key and no game data. The XEX writer is fetched as a pinned dependency from
`kleinergoo7/XexTool-Zig` (GPL-3.0-or-later); this repository contains no key constants.

## Build and test

```
zig build
zig build test
```

These need no ISO, no key and no game files. The first build downloads the pinned XEX writer
dependency from GitHub.

## Try it

```
# Disc -> tree
zig build extract -Diso=<disc.iso> -Dout=data/gta4

# Header only, no key
zig build analyze -Dtree=data/gta4

# Decrypt and list sections
zig build analyze -Dtree=data/gta4 -Dkey=<key>

# Convert a retail XEX to an unencrypted, uncompressed copy
zig build xex -Dxex=<retail.xex> -Dout=<unlocked.xex> -Dkey=<key>

# Whole-image coverage report
zig build coverage -Dxex=<unlocked.xex>

# Emit a slice of guest functions as Zig
zig build codegen -Dxex=<unlocked.xex> -Dout=zig-out/codegen -Dslice=20

# Differential gate on the frozen function list
zig build gate -Dxex=<unlocked.xex> -Dslice-list=tests/slice/addresses.json

# Cross-compile check
zig build portability
```

All paths are ordinary strings. `data/` is gitignored; extracted game files, XEX files, keys and
oracle traces never enter the repository.

## Keys

Resolution order, first match wins:

1. `--key <path>`
2. `REZIG_XEX_KEY` (a path)
3. `~/.config/rezig/xex.key`

The file must be exactly 16 raw bytes. A retail key is disc-independent. The game-specific
session key lives inside each XEX and is never stored by rezig.

`rezig xex` uses the caller's key to read the image and links only the writer side of the XEX
tool. The linked library takes console keys as parameters; rezig's binary contains no AES key
constants and no signing private key.

The 32-byte `aes_key.bin` distributed with some GTA IV mods is the RPF archive key, not the XEX
key. rezig rejects it with `BadKeySize`.

## Layout

| Path | Contents |
|---|---|
| `src/disc` | ISO and XDVDFS reader |
| `src/xex` | XEX header, AES, image decrypt, PE parse |
| `src/ppc` | instruction decode, function discovery, `.pdata` |
| `src/codegen` | slice selection and Zig emitter |
| `src/interp` | reference interpreter used by the gate |
| `src/runtime` | guest context and memory window |
| `src/cli` | command parsing and commands |
| `tests/gate.zig` | emitted-vs-interpreter differential test |
| `docs/STATUS.md` | verified facts, bugs, limits, roadmap |

## Roadmap

1. Complete the decoder and VMX, measured by `zig build coverage`.
2. Lower indirect calls and branches.
3. Emit the whole image in chunks and compile it.
4. Minimal kernel HLE: memory, threads, events, files, timing.
5. Xenos command capture, then shaders, textures and Vulkan presentation.
6. Audio, input, saves.
7. Performance work.

## Licence

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.

GTA IV, Xbox 360 and Xenos are trademarks of their respective owners. This project is not
affiliated with Microsoft, Rockstar Games or Take-Two Interactive. It ships no game code, assets
or keys.
