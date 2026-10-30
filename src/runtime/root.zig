//! Guest runtime: context, memory and (later) dispatch.

pub const ctx = @import("ctx.zig");
pub const memory = @import("memory.zig");

test {
    _ = ctx;
    _ = memory;
}
