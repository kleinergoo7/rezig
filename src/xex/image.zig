//! XEX image loading: session key, payload decryption, basic decompression, PE parse.

const std = @import("std");
const Io = std.Io;
const header = @import("header.zig");
const aes = @import("aes.zig");

pub const MAX_XEX: u64 = 0x8000_0000;
pub const MAX_HEADER: u32 = 1 << 20;
pub const CHUNK: usize = 1 << 20;
pub const MAX_SECTIONS: u32 = 96;
pub const SIZEOF_SECTION_HEADER: u32 = 40;
pub const SIZEOF_OPTIONAL_HEADER: u16 = 0xE0;

pub const Error = header.Error || error{
    ImageSizeMismatch,
    WrongKey,
    BadPe,
    NotPowerPc,
    TooLarge,
    KeyMissing,
} || aes.DecryptError || std.Io.File.OpenError || std.Io.File.StatError || std.Io.File.ReadPositionalError;

pub const PeSection = struct {
    name: [8]u8,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
};

pub const Image = struct {
    bytes: []u8,
    base_address: u32,
    entry_point: u32,
    sections: []PeSection,
    version: header.Version,
    title_id: u32,
    media_id: u32,

    pub fn deinit(self: *Image, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.sections);
        self.* = undefined;
    }

    pub fn sectionBytes(self: *const Image, section: PeSection) []const u8 {
        return self.bytes[section.virtual_address..][0..section.virtual_size];
    }

    pub fn isExecutable(self: *const Image, section: PeSection) bool {
        _ = self;
        return section.characteristics & 0x2000_0000 != 0;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: Io,
    xex_path: []const u8,
    key: ?[16]u8,
) Error!Image {
    const file = try Io.Dir.cwd().openFile(io, xex_path, .{});
    defer file.close(io);

    const st = try file.stat(io);
    if (st.size > MAX_XEX) return error.TooLarge;

    const bytes = try allocator.alloc(u8, @intCast(st.size));
    defer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.Truncated;

    return loadBytes(allocator, bytes, key);
}

pub fn loadBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    key: ?[16]u8,
) Error!Image {
    if (bytes.len < 0x1000) return error.Truncated;

    const header_size = std.mem.readInt(u32, bytes[8..12], .big);
    if (header_size < 0x18 or header_size > MAX_HEADER) return error.Truncated;
    if (header_size > bytes.len or header_size % 16 != 0) return error.Truncated;

    var h = try header.parse(allocator, bytes);
    defer h.deinit(allocator);

    const payload_len = bytes.len - header_size;
    // AES needs whole blocks; an unencrypted payload has no such constraint.
    if (h.file_format.encryption == .normal and payload_len % 16 != 0) return error.Truncated;

    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memcpy(payload, bytes[header_size..]);

    if (h.security.image_size == 0) return error.ImageSizeMismatch;

    if (h.file_format.encryption == .normal) {
        const supplied = key orelse return error.KeyMissing;
        var session_key: [16]u8 = undefined;
        try aes.decryptCbc(supplied, std.mem.zeroes([16]u8), &h.security.wrapped_key, &session_key);
        try decryptPayload(session_key, payload);
    }

    const image_bytes = try allocator.alloc(u8, h.security.image_size);
    errdefer allocator.free(image_bytes);

    switch (h.file_format.compression) {
        .none => {
            if (payload.len < image_bytes.len) return error.Truncated;
            @memcpy(image_bytes, payload[0..image_bytes.len]);
        },
        .basic => try decompressBasic(payload, image_bytes, h.file_format.blocks),
        .normal => return error.UnsupportedCompression,
    }

    const pe = try parsePe(allocator, image_bytes, h.file_format.encryption == .normal);
    errdefer allocator.free(pe.sections);

    return .{
        .bytes = image_bytes,
        .base_address = pe.base_address,
        .entry_point = pe.entry_point,
        .sections = pe.sections,
        .version = h.execution.version,
        .title_id = h.execution.title_id,
        .media_id = h.execution.media_id,
    };
}

fn decryptPayload(session_key: [16]u8, payload: []u8) aes.DecryptError!void {
    var iv = std.mem.zeroes([16]u8);
    var offset: usize = 0;
    while (offset < payload.len) {
        const n = @min(CHUNK, payload.len - offset);
        // The next chunk's IV is the last ciphertext block before decryption overwrites it.
        const next_iv = if (offset + n < payload.len) payload[offset + n - 16 ..][0..16].* else iv;
        try aes.decryptCbc(session_key, iv, payload[offset..][0..n], payload[offset..][0..n]);
        iv = next_iv;
        offset += n;
    }
}

fn decompressBasic(payload: []const u8, out: []u8, blocks: []const header.Block) Error!void {
    var in_pos: usize = 0;
    var out_pos: usize = 0;
    for (blocks) |block| {
        const data_size: usize = block.data_size;
        const zero_size: usize = block.zero_size;
        if (in_pos + data_size > payload.len) return error.Truncated;
        if (out_pos + data_size + zero_size > out.len) return error.ImageSizeMismatch;

        @memcpy(out[out_pos..][0..data_size], payload[in_pos..][0..data_size]);
        out_pos += data_size;
        in_pos += data_size;
        @memset(out[out_pos..][0..zero_size], 0);
        out_pos += zero_size;
    }
    if (out_pos != out.len) return error.ImageSizeMismatch;
}

const Pe = struct { base_address: u32, entry_point: u32, sections: []PeSection };

fn parsePe(allocator: std.mem.Allocator, bytes: []const u8, encrypted: bool) Error!Pe {
    const invalid = if (encrypted) error.WrongKey else error.BadPe;

    if (bytes.len < 0x40) return invalid;
    if (bytes[0] != 'M' or bytes[1] != 'Z') return invalid;

    const lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    if (lfanew < 0x40) return invalid;
    if (@as(u64, lfanew) + 24 > bytes.len) return invalid;
    if (!std.mem.eql(u8, bytes[lfanew..][0..4], "PE\x00\x00")) return invalid;

    const file_header = bytes[lfanew + 4 ..];
    const machine = std.mem.readInt(u16, file_header[0..2], .little);
    if (machine != 0x01F2) return if (encrypted) error.WrongKey else error.NotPowerPc;

    const section_count = std.mem.readInt(u16, file_header[2..4], .little);
    if (section_count == 0 or section_count > MAX_SECTIONS) return invalid;

    const optional_size = std.mem.readInt(u16, file_header[16..18], .little);
    if (optional_size < SIZEOF_OPTIONAL_HEADER) return invalid;

    const optional = lfanew + 24;
    if (@as(u64, optional) + optional_size > bytes.len) return invalid;
    if (std.mem.readInt(u16, bytes[optional..][0..2], .little) != 0x010B) return invalid;

    const entry_rva = std.mem.readInt(u32, bytes[optional + 16 ..][0..4], .little);
    const base_address = std.mem.readInt(u32, bytes[optional + 28 ..][0..4], .little);
    const size_of_image = std.mem.readInt(u32, bytes[optional + 56 ..][0..4], .little);

    if (size_of_image > bytes.len) return invalid;
    if (entry_rva >= size_of_image) return invalid;

    const table = optional + @as(u32, optional_size);
    const table_len = @as(u64, section_count) * SIZEOF_SECTION_HEADER;
    if (table + table_len > bytes.len) return invalid;

    const sections = try allocator.alloc(PeSection, section_count);
    errdefer allocator.free(sections);

    for (sections, 0..) |*section, i| {
        const at = table + @as(u32, @intCast(i)) * SIZEOF_SECTION_HEADER;
        const raw = bytes[at..];
        const virtual_size = std.mem.readInt(u32, raw[8..12], .little);
        const virtual_address = std.mem.readInt(u32, raw[12..16], .little);
        if (virtual_address > bytes.len) return invalid;
        if (virtual_size > bytes.len - virtual_address) return invalid;

        section.* = .{
            .name = raw[0..8].*,
            .virtual_size = virtual_size,
            .virtual_address = virtual_address,
            .raw_size = std.mem.readInt(u32, raw[16..20], .little),
            .raw_offset = std.mem.readInt(u32, raw[20..24], .little),
            .characteristics = std.mem.readInt(u32, raw[36..40], .little),
        };
    }

    return .{
        .base_address = base_address,
        .entry_point = base_address +% entry_rva,
        .sections = sections,
    };
}

const testing = std.testing;
const xex_writer = @import("../fixtures/xex_writer.zig");

const zero_key: [16]u8 = std.mem.zeroes([16]u8);

fn writeFixture(
    io: Io,
    tmp: *testing.TmpDir,
    name: []const u8,
    data: []const u8,
    path_buf: []u8,
) ![]const u8 {
    try tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
    return std.fmt.bufPrint(path_buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

test "load returns the exact pe image and its sections" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(bytes);
    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "fixture.xex", bytes, &path_buf);

    var img = try load(testing.allocator, io, path, zero_key);
    defer img.deinit(testing.allocator);

    const expected = try xex_writer.buildPeImage(testing.allocator);
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, img.bytes);

    try testing.expectEqual(xex_writer.pe_image_base, img.base_address);
    try testing.expectEqual(xex_writer.pe_image_base + xex_writer.pe_entry_rva, img.entry_point);
    try testing.expectEqual(@as(usize, 2), img.sections.len);
    try testing.expectEqualStrings(".text", std.mem.sliceTo(&img.sections[0].name, 0));
    try testing.expectEqualStrings(".data", std.mem.sliceTo(&img.sections[1].name, 0));
    try testing.expect(img.isExecutable(img.sections[0]));
    try testing.expect(!img.isExecutable(img.sections[1]));
    try testing.expectEqual(@as(usize, 0x800), img.sectionBytes(img.sections[0]).len);
}

test "wrong key is reported as wrong key" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 1, 1);
    defer testing.allocator.free(bytes);
    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "encrypted.xex", bytes, &path_buf);

    try testing.expectError(error.WrongKey, load(testing.allocator, io, path, zero_key));
}

test "normal compression is refused by name" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 2);
    defer testing.allocator.free(bytes);
    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "normal.xex", bytes, &path_buf);

    try testing.expectError(error.UnsupportedCompression, load(testing.allocator, io, path, zero_key));
}

test "block sum mismatch is an image size mismatch" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(bytes);
    std.mem.writeInt(u32, bytes[xex_writer.off.file_format + 16 ..][0..4], 0x800, .big);

    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "short.xex", bytes, &path_buf);

    try testing.expectError(error.ImageSizeMismatch, load(testing.allocator, io, path, zero_key));
}

test "missing mz is a bad pe" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(bytes);
    bytes[xex_writer.header_size] = 0;

    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "nomz.xex", bytes, &path_buf);

    try testing.expectError(error.BadPe, load(testing.allocator, io, path, zero_key));
}

test "non powerpc machine is refused" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(bytes);
    const machine_at = xex_writer.header_size + 0x80 + 4;
    std.mem.writeInt(u16, bytes[machine_at..][0..2], 0x014C, .little);

    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "x86.xex", bytes, &path_buf);

    try testing.expectError(error.NotPowerPc, load(testing.allocator, io, path, zero_key));
}

test "chunked decryption matches a single pass" {
    const key: [16]u8 = @splat(7);
    const size = 2 * 1024 * 1024 + 512 * 1024;

    const chunked = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(chunked);
    const single = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(single);

    for (chunked, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 7);
    @memcpy(single, chunked);

    try decryptPayload(key, chunked);
    try aes.decryptCbc(key, std.mem.zeroes([16]u8), single, single);

    try testing.expectEqualSlices(u8, single, chunked);
}

test "zero blocks are inserted" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(bytes);

    const ff = bytes[xex_writer.off.file_format..];
    std.mem.writeInt(u32, ff[8..12], 0x200, .big);
    std.mem.writeInt(u32, ff[12..16], 0x600, .big);
    std.mem.writeInt(u32, ff[16..20], 0x1800, .big);
    std.mem.writeInt(u32, ff[20..24], 0, .big);

    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "zeros.xex", bytes, &path_buf);

    var img = try load(testing.allocator, io, path, zero_key);
    defer img.deinit(testing.allocator);

    const expected = try xex_writer.buildPeImage(testing.allocator);
    defer testing.allocator.free(expected);

    try testing.expectEqualSlices(u8, expected[0..0x200], img.bytes[0..0x200]);
    for (img.bytes[0x200..0x800]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    try testing.expectEqualSlices(u8, expected[0x200..0x400], img.bytes[0x800..0xa00]);
}

test "encrypted input without a key reports key missing" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bytes = try xex_writer.buildFull(testing.allocator, 1, 1);
    defer testing.allocator.free(bytes);
    var path_buf: [256]u8 = undefined;
    const path = try writeFixture(io, &tmp, "encrypted-nokey.xex", bytes, &path_buf);

    try testing.expectError(error.KeyMissing, load(testing.allocator, io, path, null));
}
