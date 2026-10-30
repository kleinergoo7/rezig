# Rezig

Static recompilation for Xbox 360, in Zig. Input: a disc image. Output: Zig source for the
guest's PowerPC functions, plus the runtime they run on.

Pilot title: Grand Theft Auto IV, USA disc 1.0, base game, no title update.

## Requirements

- Zig 0.17.0, invoked as `/home/linuxbrew/.linuxbrew/bin/zig` on this machine.
- A legal copy of the disc image.
- For real code: a 16-byte XEX key of your own, or an already-unlocked XEX.

rezig ships no key and no game data, and never will.

## Try it

```
zig build                       # build the CLI
zig build test                  # unit, fixture and golden tests; no ISO, no key

zig build extract -Diso=<disc.iso> -Dout=data/gta4
zig build analyze -Dtree=data/gta4                 # header only; needs no key
zig build analyze -Dtree=data/gta4 -Dkey=<key>     # decrypts and lists PE sections
zig build codegen -Dxex=<unlocked.xex> -Dout=zig-out/codegen -Dslice=20
zig build gate -Dxex=<unlocked.xex> -Dslice-list=tests/slice/addresses.json
zig build portability           # x86_64-windows and aarch64-linux compile gate
```

## Keys

Resolution order, first match wins:

1. `--key <path>`
2. `REZIG_XEX_KEY` (a path)
3. `~/.config/rezig/xex.key`

The file must be exactly 16 raw bytes. One retail key works for every retail disc; it is not
game-specific. The game-specific session key lives inside each XEX and is never stored by us.

Without a key, use `--xex` with an already-decrypted image. `zig build unlock -Dxex=<xex>
-Dxextool=<XexTool binary>` wraps the external tool temporarily; P1 replaces it with `rezig xex`.

The 32-byte `aes_key.bin` shipped by some GTA IV mods is the RPF key, not the XEX key. rezig
rejects it with `BadKeySize`.

## Status

See `docs/STATUS.md`. P0 covers extraction and a 20-function compile gate; the differential gate
needs oracle traces that are not in this repo yet.

## Licence

Not chosen yet.
