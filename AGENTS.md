# Agent rules (rezig)

Canonical policy for every coding agent in this repo. Precedence: user's
current request, then this file, then `docs/`.

## 0. Project facts

- Language: Zig 0.17.0 exactly (`/home/linuxbrew/.linuxbrew/bin/zig`).
- Build: `zig build`. Test: `zig build test`. Format: `zig fmt .`.
- Release build: `zig build -Doptimize=ReleaseFast`.
- After every change run `zig fmt .`, `zig build`, `zig build test` and report.
- Fixtures are git-ignored under `data/`; test images stay outside the repo.
  No test reads real fixtures today (`zig build test` is fully synthetic).
  The first test that needs one must take its path from `REZIG_FIXTURE_DIR`
  (same naming scheme as `REZIG_XEX_KEY`), skip with a clear message when
  unset, and never write into it.

## 1. Build and verify

- Build and test with the project commands above. No shell/Python/CMake for build/test.
- Run the formatter before building after every code change.
- Decide success from the process exit status, never from grepping tool output.
  Tools can emit localized messages, so text grep can report zero errors on failure.
- After a build that can fail, confirm the output artifact actually changed
  (mtime or hash). Stale artifact reads exactly like successful build.
- Every claim cites command + exit status + output. No "done"/"fixed"/"works" bare.
- New native or third-party dependency: say so in the change.
- `.zig-cache` has a hard 5 GiB cap, enforced by `enforceCacheCap` in
  `build.zig` (trims oldest entries on every build). Never disable it.

## 2. Language, style, boundaries

- New code uses pinned Zig; never write std APIs from memory. Read installed
  lib source for that exact version first.
- No second language in product code. Everything Xbox 360 in Zig.
- Standard naming, short functions, early returns, shallow nesting.
- Comments explain why (spec fact, offset, bug); never what line does.
- No magic numbers; use named constants for offsets and flags. No unrelated churn.
- Parsing code does not know about UI; writer code does not parse inputs.

## 3. Errors must fail loudly

Silence worse than crash: wrong result that looks valid.

- No empty catch, swallowed error, hiding default, silent retry, silent skip.
- No `unreachable`/panic/unchecked-unwrap for anything user or input file can
  trigger. Named error plus message naming what failed and on which input:
  file path, entry path, header field, byte offset.
- Refusals are data: kind, file, field/path, user-facing sentence. CLI prints verbatim.
- Log at point of failure before returning. Core code keeps diagnostics in
  result type; existing `std.debug.print` call sites stay until replaced by
  named log helper (no drive-by rework).
- No partial output survives failure: temp/`.part` files deleted on error,
  cancel, crash paths. Run completes correctly or produces no output file.
- Warnings are errors during development. Cannot validate: refuse, never guess.
- Never downgrade error to log line so run can continue.

## 4. Tests

- Every function with branch, loop, parser, or arithmetic on file data gets test.
- Real fixtures via `REZIG_FIXTURE_DIR`. Tests skip with clear message when
  unset; never fail for missing fixture. Never write into fixture dir.
- Cover failure side of every refusal: one test per named error.
- Names state behavior. Assert concrete values: magic bytes, counts, totals, hashes.
- Test passing without its fixture present is not evidence. Say which fixture needed.
- CI has no proprietary fixtures: keep synthetic fixture builder valid and
  exercising main paths. Update it when format handling changes.

## 5. Parsing and untrusted input

- Fixed-width integer types for anything read from file. Never platform-sized
  type for on-disk values.
- Bounds-check every read against real input length first. Truncated input is
  normal failure mode, not edge case.
- Check arithmetic on file-controlled values for overflow before use in
  sizes, offsets, allocations.
- Layouts explicit (packed/extern structs or byte-level decode); assert sizes
  at compile time or in test.
- Comment every unchecked/narrowing cast with why safe, naming check that makes valid.

## 6. Streaming and disk

- Never materialize large extracted artifact in full. Stream entry by entry.
  (Decrypted XEX image held in memory is current design exception.)
- Cap disk spill and abort before filling disk.
- Write output to temp name, rename only after verification passes.
- Open inputs read-only. Never write next to input without user choosing it.
  Refuse symlinks and special files instead of following them.

## 7. Git and repository hygiene

- No game files, ISOs, XEX files, extracted trees, or keys in git.
- Small commits, one reason each. Build fixes and behavior fixes land separately.
- Never force-push, never rewrite history without backup branch.
- Workaround labelled `WORKAROUND`, states why, logs every trigger.
  Silent workarounds are bugs.

## 8. When unsure

- API, offset, or format fact unverifiable: stop and say so. Never guess field/signature.
- Prefer refusing input over output that may be wrong.
