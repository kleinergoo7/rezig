//! Test root. Every module is referenced here so its tests run under `zig build test`.

test {
    _ = @import("cli/root.zig");
    _ = @import("cli/parse.zig");
}
