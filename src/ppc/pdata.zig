//! `.pdata`: the Xbox 360 exception directory, 8 bytes per function.
//! First u32 is the function start VA; the second is packed unwind data.

const std = @import("std");

pub const entry_size: usize = 8;

/// Returns every nonzero function start in file order. Callers filter by
/// executable section.
pub fn starts(allocator: std.mem.Allocator, bytes: []const u8) ![]u32 {
    if (bytes.len < entry_size) return &.{};
    const count = bytes.len / entry_size;
    var list: std.ArrayList(u32) = .empty;
    errdefer list.deinit(allocator);

    for (0..count) |i| {
        const at = i * entry_size;
        const start = std.mem.readInt(u32, bytes[at..][0..4], .big);
        if (start == 0 or start == 0xffff_ffff) continue;
        try list.append(allocator, start);
    }
    return list.toOwnedSlice(allocator);
}

const testing = std.testing;

test "reads big-endian starts and skips sentinels" {
    const bytes = [_]u8{
        0x82, 0x12, 0x00, 0x00, 0x40, 0x00, 0x29, 0x04,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x82, 0x12, 0x00, 0xa8, 0x40, 0x00, 0x09, 0x03,
    };
    const got = try starts(testing.allocator, &bytes);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u32, &.{ 0x82120000, 0x821200A8 }, got);
}
