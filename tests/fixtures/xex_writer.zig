//! Synthetic XEX2 images for tests. No game bytes.

const std = @import("std");

pub const magic: u32 = 0x58455832; // 'XEX2'
pub const header_size: u32 = 0x240;

pub const off = struct {
    pub const magic_field = 0x00;
    pub const module_flags = 0x04;
    pub const payload_offset = 0x08;
    pub const security_offset = 0x10;
    pub const header_count = 0x14;
    pub const optional = 0x18;
    pub const security = 0x60;
    pub const file_format = 0x1E0;
    pub const execution = 0x200;
};

pub const key_file_format: u32 = 0x000003FF;
pub const key_entry_point: u32 = 0x00010100;
pub const key_image_base: u32 = 0x00010201;
pub const key_execution: u32 = 0x00040006;

pub const entry_point: u32 = 0x82001000;
pub const image_base: u32 = 0x82000000;
pub const image_size: u32 = 0x3000;
pub const title_id: u32 = 0x545407F2;
pub const media_id: u32 = 0x6AC07221;

pub fn build(allocator: std.mem.Allocator) ![]u8 {
    const bytes = try allocator.alloc(u8, header_size);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);

    std.mem.writeInt(u32, bytes[off.magic_field..][0..4], magic, .big);
    std.mem.writeInt(u32, bytes[off.module_flags..][0..4], 1, .big);
    std.mem.writeInt(u32, bytes[off.payload_offset..][0..4], header_size, .big);
    std.mem.writeInt(u32, bytes[off.security_offset..][0..4], off.security, .big);
    std.mem.writeInt(u32, bytes[off.header_count..][0..4], 4, .big);

    const headers = [_][2]u32{
        .{ key_file_format, off.file_format },
        .{ key_entry_point, entry_point },
        .{ key_image_base, image_base },
        .{ key_execution, off.execution },
    };
    for (headers, 0..) |h, i| {
        const at = off.optional + i * 8;
        std.mem.writeInt(u32, bytes[at..][0..4], h[0], .big);
        std.mem.writeInt(u32, bytes[at + 4 ..][0..4], h[1], .big);
    }

    const sec = bytes[off.security..];
    std.mem.writeInt(u32, sec[0..4], 0x180, .big);
    std.mem.writeInt(u32, sec[4..8], image_size, .big);
    for (sec[0x150..][0..16], 0..) |*b, i| b.* = @intCast(i);
    std.mem.writeInt(u32, sec[0x178..][0..4], 0xFF, .big);
    std.mem.writeInt(u32, sec[0x17C..][0..4], 4, .big);

    const ff = bytes[off.file_format..];
    std.mem.writeInt(u32, ff[0..4], 24, .big);
    std.mem.writeInt(u16, ff[4..6], 1, .big);
    std.mem.writeInt(u16, ff[6..8], 1, .big);
    std.mem.writeInt(u32, ff[8..12], 0x2000, .big);
    std.mem.writeInt(u32, ff[12..16], 0, .big);
    std.mem.writeInt(u32, ff[16..20], 0x1000, .big);
    std.mem.writeInt(u32, ff[20..24], 0, .big);

    const ex = bytes[off.execution..];
    std.mem.writeInt(u32, ex[0..4], media_id, .big);
    std.mem.writeInt(u32, ex[4..8], 0x00000005, .big);
    std.mem.writeInt(u32, ex[8..12], 0x00000005, .big);
    std.mem.writeInt(u32, ex[12..16], title_id, .big);
    ex[0x10] = 0;
    ex[0x11] = 1;
    ex[0x12] = 1;
    ex[0x13] = 1;

    return bytes;
}
