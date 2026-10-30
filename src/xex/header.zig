//! XEX2 header, optional headers, security block and file format info.

const std = @import("std");

pub const MAGIC: u32 = 0x58455832; // 'XEX2'

pub const FILE_FORMAT_INFO: u32 = 0x000003FF;
pub const ENTRY_POINT: u32 = 0x00010100;
pub const IMAGE_BASE_ADDRESS: u32 = 0x00010201;
pub const EXECUTION_INFO: u32 = 0x00040006;

pub const Error = error{
    NotXex2,
    Truncated,
    NoOptionalHeaders,
    MissingFileFormatInfo,
    MissingExecutionInfo,
    MissingEntryPoint,
    MissingImageBase,
    UnsupportedEncryption,
    UnsupportedCompression,
    OutOfMemory,
};

pub const Version = struct {
    value: u32,

    /// Upper nibble.
    pub fn major(self: Version) u4 {
        return @truncate(self.value >> 28);
    }

    /// Second nibble.
    pub fn minor(self: Version) u4 {
        return @truncate(self.value >> 24);
    }

    /// Middle 16 bits.
    pub fn build(self: Version) u16 {
        return @truncate(self.value >> 8);
    }

    /// Low byte.
    pub fn qfe(self: Version) u8 {
        return @truncate(self.value);
    }

    pub fn eql(self: Version, other: Version) bool {
        return self.value == other.value;
    }
};

pub const Encryption = enum { none, normal };
pub const Compression = enum { none, basic, normal };

pub const Block = struct { data_size: u32, zero_size: u32 };

pub const FileFormat = struct {
    encryption: Encryption,
    compression: Compression,
    blocks: []const Block,
};

pub const Execution = struct {
    media_id: u32,
    version: Version,
    base_version: Version,
    title_id: u32,
    disc_number: u8,
    disc_count: u8,
};

pub const Security = struct {
    image_size: u32,
    entry_point: u32,
    image_base: u32,
    region: u32,
    allowed_media_types: u32,
    wrapped_key: [16]u8,
};

pub const Header = struct {
    module_flags: u32,
    header_size: u32,
    security_offset: u32,
    file_format: FileFormat,
    execution: Execution,
    security: Security,

    pub fn deinit(self: *const Header, allocator: std.mem.Allocator) void {
        allocator.free(self.file_format.blocks);
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!Header {
    if (bytes.len < 0x18) return error.Truncated;
    if (readU32(bytes, 0) != MAGIC) return error.NotXex2;

    const module_flags = readU32(bytes, 0x04);
    const header_size = readU32(bytes, 0x08);
    const security_offset = readU32(bytes, 0x10);
    const header_count = readU32(bytes, 0x14);
    if (header_count == 0) return error.NoOptionalHeaders;
    if (0x18 + @as(u64, header_count) * 8 > bytes.len) return error.Truncated;

    var file_format_offset: ?u32 = null;
    var execution_offset: ?u32 = null;
    var entry_point: ?u32 = null;
    var image_base: ?u32 = null;

    var i: u32 = 0;
    while (i < header_count) : (i += 1) {
        const at = 0x18 + i * 8;
        const key = readU32(bytes, at);
        const value = readU32(bytes, at + 4);
        switch (key) {
            FILE_FORMAT_INFO => file_format_offset = value,
            EXECUTION_INFO => execution_offset = value,
            ENTRY_POINT => entry_point = value,
            IMAGE_BASE_ADDRESS => image_base = value,
            else => {},
        }
    }

    if (@as(u64, security_offset) + 0x180 > bytes.len) return error.Truncated;
    const sec = bytes[security_offset..];
    const security = Security{
        .image_size = readU32(sec, 0x004),
        .entry_point = entry_point orelse return error.MissingEntryPoint,
        .image_base = image_base orelse return error.MissingImageBase,
        .region = readU32(sec, 0x178),
        .allowed_media_types = readU32(sec, 0x17C),
        .wrapped_key = sec[0x150..][0..16].*,
    };

    const ff_offset = file_format_offset orelse return error.MissingFileFormatInfo;
    if (@as(u64, ff_offset) + 8 > bytes.len) return error.Truncated;
    const info_size = readU32(bytes, ff_offset);
    const encryption: Encryption = switch (readU16(bytes, ff_offset + 4)) {
        0 => .none,
        1 => .normal,
        else => return error.UnsupportedEncryption,
    };
    const compression: Compression = switch (readU16(bytes, ff_offset + 6)) {
        0 => .none,
        1 => .basic,
        2 => return error.UnsupportedCompression,
        else => return error.UnsupportedCompression,
    };

    var blocks: []const Block = &.{};
    errdefer if (blocks.len != 0) allocator.free(blocks);
    if (compression == .basic) {
        if (info_size < 8) return error.Truncated;
        if (@as(u64, ff_offset) + info_size > bytes.len) return error.Truncated;
        const payload = info_size - 8;
        if (payload % 8 != 0) return error.Truncated;

        const count = payload / 8;
        const allocated = try allocator.alloc(Block, count);
        for (allocated, 0..) |*block, b| {
            const at = ff_offset + 8 + @as(u32, @intCast(b)) * 8;
            block.* = .{
                .data_size = readU32(bytes, at),
                .zero_size = readU32(bytes, at + 4),
            };
        }
        blocks = allocated;
    }

    const exec_offset = execution_offset orelse return error.MissingExecutionInfo;
    if (@as(u64, exec_offset) + 0x18 > bytes.len) return error.Truncated;
    const ex = bytes[exec_offset..];
    const execution = Execution{
        .media_id = readU32(ex, 0x00),
        .version = .{ .value = readU32(ex, 0x04) },
        .base_version = .{ .value = readU32(ex, 0x08) },
        .title_id = readU32(ex, 0x0C),
        .disc_number = ex[0x12],
        .disc_count = ex[0x13],
    };

    return .{
        .module_flags = module_flags,
        .header_size = header_size,
        .security_offset = security_offset,
        .file_format = .{ .encryption = encryption, .compression = compression, .blocks = blocks },
        .execution = execution,
        .security = security,
    };
}

fn readU32(bytes: []const u8, offset: u32) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .big);
}

fn readU16(bytes: []const u8, offset: u32) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .big);
}

const testing = std.testing;
const xex_writer = @import("../fixtures/xex_writer.zig");

fn fixture() ![]u8 {
    return xex_writer.build(testing.allocator);
}

test "parse exposes the fixture header" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);

    var h = try parse(testing.allocator, bytes);
    defer h.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 1), h.module_flags);
    try testing.expectEqual(xex_writer.header_size, h.header_size);
    try testing.expectEqual(xex_writer.image_size, h.security.image_size);
    try testing.expectEqual(xex_writer.entry_point, h.security.entry_point);
    try testing.expectEqual(xex_writer.image_base, h.security.image_base);
    try testing.expectEqual(@as(u32, 0xFF), h.security.region);
    try testing.expectEqual(@as(u32, 4), h.security.allowed_media_types);
    for (h.security.wrapped_key, 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i)), b);

    try testing.expectEqual(Encryption.normal, h.file_format.encryption);
    try testing.expectEqual(Compression.basic, h.file_format.compression);
    try testing.expectEqual(@as(usize, 2), h.file_format.blocks.len);
    try testing.expectEqual(@as(u32, 0x2000), h.file_format.blocks[0].data_size);
    try testing.expectEqual(@as(u32, 0), h.file_format.blocks[0].zero_size);
    try testing.expectEqual(@as(u32, 0x1000), h.file_format.blocks[1].data_size);

    try testing.expectEqual(xex_writer.media_id, h.execution.media_id);
    try testing.expectEqual(xex_writer.title_id, h.execution.title_id);
    try testing.expectEqual(@as(u8, 1), h.execution.disc_number);
    try testing.expectEqual(@as(u8, 1), h.execution.disc_count);
    try testing.expectEqual(@as(u32, 5), h.execution.version.value);
}

test "version fields decode 0.0.0.5 and 0.0.8.0" {
    const v5 = Version{ .value = 0x00000005 };
    try testing.expectEqual(@as(u4, 0), v5.major());
    try testing.expectEqual(@as(u4, 0), v5.minor());
    try testing.expectEqual(@as(u16, 0), v5.build());
    try testing.expectEqual(@as(u8, 5), v5.qfe());

    const v8 = Version{ .value = 0x00000800 };
    try testing.expectEqual(@as(u4, 0), v8.major());
    try testing.expectEqual(@as(u4, 0), v8.minor());
    try testing.expectEqual(@as(u16, 8), v8.build());
    try testing.expectEqual(@as(u8, 0), v8.qfe());
    try testing.expect(!v5.eql(v8));
}

test "bad magic is rejected" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[xex_writer.off.magic_field..][0..4], 0, .big);
    try testing.expectError(error.NotXex2, parse(testing.allocator, bytes));
}

test "truncated header is rejected" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    try testing.expectError(error.Truncated, parse(testing.allocator, bytes[0..0x10]));
}

test "no optional headers is rejected" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[xex_writer.off.header_count..][0..4], 0, .big);
    try testing.expectError(error.NoOptionalHeaders, parse(testing.allocator, bytes));
}

test "missing file format info is rejected" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    const at = xex_writer.off.optional;
    std.mem.writeInt(u32, bytes[at..][0..4], 0x000003FE, .big);
    try testing.expectError(error.MissingFileFormatInfo, parse(testing.allocator, bytes));
}

test "missing execution info is rejected" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    const at = xex_writer.off.optional + 3 * 8;
    std.mem.writeInt(u32, bytes[at..][0..4], 0x00040007, .big);
    try testing.expectError(error.MissingExecutionInfo, parse(testing.allocator, bytes));
}

test "file format offset past the buffer is truncated" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    const at = xex_writer.off.optional + 4;
    std.mem.writeInt(u32, bytes[at..][0..4], 0xFFFF, .big);
    try testing.expectError(error.Truncated, parse(testing.allocator, bytes));
}

test "basic block count must divide evenly" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[xex_writer.off.file_format..][0..4], 25, .big);
    try testing.expectError(error.Truncated, parse(testing.allocator, bytes));
}

test "normal compression is refused by name" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    const at = xex_writer.off.file_format + 6;
    std.mem.writeInt(u16, bytes[at..][0..2], 2, .big);
    try testing.expectError(error.UnsupportedCompression, parse(testing.allocator, bytes));
}

test "unknown encryption is refused by name" {
    const bytes = try fixture();
    defer testing.allocator.free(bytes);
    const at = xex_writer.off.file_format + 4;
    std.mem.writeInt(u16, bytes[at..][0..2], 3, .big);
    try testing.expectError(error.UnsupportedEncryption, parse(testing.allocator, bytes));
}
