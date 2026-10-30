//! PowerPC subsystem: decode, disassembly and function discovery.

pub const analyze = @import("analyze.zig");
pub const decode = @import("decode.zig");
pub const pdata = @import("pdata.zig");

test {
    _ = analyze;
    _ = decode;
    _ = pdata;
}
