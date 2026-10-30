//! Generated-code ABI: names and version.

const std = @import("std");

pub const version: u32 = 1;

/// Writes `g_XXXXXXXX` into `buf` and returns it.
pub fn fnName(addr: u32, buf: *[10]u8) []const u8 {
    const digits = "0123456789abcdef";
    buf[0] = 'g';
    buf[1] = '_';
    var i: u5 = 0;
    while (i < 8) : (i += 1) {
        const shift: u5 = @intCast((7 - i) * 4);
        buf[2 + i] = digits[(addr >> shift) & 0xf];
    }
    return buf;
}

test "function names are ten lowercase characters" {
    var buf: [10]u8 = undefined;
    try std.testing.expectEqualStrings("g_00000000", fnName(0, &buf));
    try std.testing.expectEqualStrings("g_829a0860", fnName(0x829A0860, &buf));
}
