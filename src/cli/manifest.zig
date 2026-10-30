//! `rezig-manifest.json`: our metadata only, no game data.

const std = @import("std");
const Io = std.Io;

pub const tool_version = "0.0.0";
pub const abi: u32 = 1;
pub const file_name = "rezig-manifest.json";
pub const digest_hex_len = 64;
pub const max_manifest_bytes: usize = 1 << 24;

pub const Entry = struct {
    path: []u8,
    size: u64,
    sha256: [digest_hex_len]u8,
};

pub const Manifest = struct {
    iso_size: u64,
    disc_base: u64,
    xex_version: [4]u16,
    title_id: u32,
    image_size: u32,
    image_verified: bool,
    image_sha256: ?[digest_hex_len]u8,
    entries: []Entry,

    pub fn deinit(self: *const Manifest, allocator: std.mem.Allocator) void {
        for (self.entries) |e| allocator.free(e.path);
        allocator.free(self.entries);
    }

    pub fn find(self: *const Manifest, path: []const u8) ?*const Entry {
        for (self.entries) |*e| {
            if (std.mem.eql(u8, e.path, path)) return e;
        }
        return null;
    }
};

pub const ReadError = error{
    ManifestNotFound,
    CorruptManifest,
    UnsupportedAbi,
} || std.Io.Dir.OpenError || std.Io.Dir.ReadFileAllocError || std.mem.Allocator.Error;

const WireEntry = struct { path: []const u8, size: u64, sha256: []const u8 };

const Wire = struct {
    abi: u32 = abi,
    tool_version: []const u8 = tool_version,
    iso_size: u64,
    disc_base: u64,
    xex_version: [4]u16,
    title_id: u32,
    image_size: u32,
    image_verified: bool,
    image_sha256: ?[]const u8,
    entries: []const WireEntry,
};

pub fn write(
    allocator: std.mem.Allocator,
    io: Io,
    dir_path: []const u8,
    m: *const Manifest,
) !void {
    const wire_entries = try allocator.alloc(WireEntry, m.entries.len);
    defer allocator.free(wire_entries);
    for (m.entries, 0..) |*e, i| {
        wire_entries[i] = .{ .path = e.path, .size = e.size, .sha256 = &e.sha256 };
    }

    var image_hex = m.image_sha256;
    const wire = Wire{
        .iso_size = m.iso_size,
        .disc_base = m.disc_base,
        .xex_version = m.xex_version,
        .title_id = m.title_id,
        .image_size = m.image_size,
        .image_verified = m.image_verified,
        .image_sha256 = if (image_hex) |*h| h else null,
        .entries = wire_entries,
    };

    const json = try std.json.Stringify.valueAlloc(allocator, wire, .{ .whitespace = .indent_2 });
    defer allocator.free(json);

    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var atomic = try dir.createFileAtomic(io, file_name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, json);
    try atomic.replace(io);
}

pub fn read(allocator: std.mem.Allocator, io: Io, dir_path: []const u8) ReadError!Manifest {
    var dir = Io.Dir.cwd().openDir(io, dir_path, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.ManifestNotFound,
        else => |other| return other,
    };
    defer dir.close(io);

    const text = dir.readFileAlloc(io, file_name, allocator, .limited(max_manifest_bytes)) catch |e| switch (e) {
        error.FileNotFound => return error.ManifestNotFound,
        error.StreamTooLong => return error.CorruptManifest,
        else => |other| return other,
    };
    defer allocator.free(text);

    var parsed = std.json.parseFromSlice(Wire, allocator, text, .{}) catch return error.CorruptManifest;
    defer parsed.deinit();

    if (parsed.value.abi != abi) return error.UnsupportedAbi;

    const entries = try allocator.alloc(Entry, parsed.value.entries.len);
    errdefer allocator.free(entries);

    var filled: usize = 0;
    errdefer {
        for (entries[0..filled]) |e| allocator.free(e.path);
    }

    for (parsed.value.entries, 0..) |wire, i| {
        if (wire.sha256.len != digest_hex_len) return error.CorruptManifest;
        entries[i] = .{
            .path = try allocator.dupe(u8, wire.path),
            .size = wire.size,
            .sha256 = wire.sha256[0..digest_hex_len].*,
        };
        filled = i + 1;
    }

    var image_hex: ?[digest_hex_len]u8 = null;
    if (parsed.value.image_sha256) |hex| {
        if (hex.len != digest_hex_len) return error.CorruptManifest;
        image_hex = hex[0..digest_hex_len].*;
    }

    return .{
        .iso_size = parsed.value.iso_size,
        .disc_base = parsed.value.disc_base,
        .xex_version = parsed.value.xex_version,
        .title_id = parsed.value.title_id,
        .image_size = parsed.value.image_size,
        .image_verified = parsed.value.image_verified,
        .image_sha256 = image_hex,
        .entries = entries,
    };
}

pub fn hexLower(bytes: []const u8, out: *[digest_hex_len]u8) void {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = alphabet[b >> 4];
        out[2 * i + 1] = alphabet[b & 0x0f];
    }
}

test "manifest round trips through json" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [256]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var digest: [digest_hex_len]u8 = undefined;
    @memset(&digest, 'a');

    const entries = try testing.allocator.alloc(Entry, 1);
    defer testing.allocator.free(entries);
    entries[0] = .{
        .path = try testing.allocator.dupe(u8, "data/inner.bin"),
        .size = 7,
        .sha256 = digest,
    };
    defer testing.allocator.free(entries[0].path);

    const m = Manifest{
        .iso_size = 1,
        .disc_base = 0xFD90000,
        .xex_version = .{ 0, 0, 0, 5 },
        .title_id = 0x545407F2,
        .image_size = 0x2000,
        .image_verified = false,
        .image_sha256 = null,
        .entries = entries,
    };

    try write(testing.allocator, io, dir_path, &m);

    var back = try read(testing.allocator, io, dir_path);
    defer back.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), back.iso_size);
    try testing.expectEqual(@as(u32, 0x545407F2), back.title_id);
    try testing.expectEqual(false, back.image_verified);
    try testing.expectEqual(@as(usize, 1), back.entries.len);
    try testing.expectEqualStrings("data/inner.bin", back.entries[0].path);
    try testing.expectEqualSlices(u8, &digest, &back.entries[0].sha256);
}

test "missing manifest is named" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try testing.expectError(error.ManifestNotFound, read(testing.allocator, io, dir_path));
}

const testing = std.testing;
