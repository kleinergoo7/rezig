//! Guest memory window. Addresses are guest addresses, never host pointers.

const std = @import("std");

pub const Memory = struct {
    base: u32,
    data: []u8,

    pub fn contains(self: Memory, addr: u32, size: u8) bool {
        if (addr < self.base) return false;
        const offset = addr - self.base;
        return offset <= self.data.len and size <= self.data.len - offset;
    }
};

test "contains checks the whole access" {
    var buf: [16]u8 = undefined;
    const mem = Memory{ .base = 0x1000, .data = &buf };
    try std.testing.expect(mem.contains(0x1000, 16));
    try std.testing.expect(mem.contains(0x100f, 1));
    try std.testing.expect(!mem.contains(0x100f, 2));
    try std.testing.expect(!mem.contains(0x0fff, 1));
    try std.testing.expect(!mem.contains(0x1010, 1));
}
