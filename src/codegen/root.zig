//! Zig emitter.

pub const abi = @import("abi.zig");
pub const emit = @import("emit.zig");
pub const slice = @import("slice.zig");

test {
    _ = abi;
    _ = emit;
    _ = slice;
}
