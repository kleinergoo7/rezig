//! Test root. Importing a module here makes its `test` blocks run under `zig build test`.

test {
    _ = @import("src/cli/root.zig");
    _ = @import("src/cli/parse.zig");
    _ = @import("src/disc/root.zig");
    _ = @import("src/xex/root.zig");
    _ = @import("src/elf/root.zig");
    _ = @import("src/ppc/root.zig");
    _ = @import("src/runtime/root.zig");
    _ = @import("src/codegen/root.zig");
}
