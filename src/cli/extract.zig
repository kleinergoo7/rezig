//! `rezig extract`: ISO -> verified game tree + manifest.

const std = @import("std");
const Io = std.Io;
const iso_mod = @import("../disc/iso.zig");
const xdvdfs = @import("../disc/xdvdfs.zig");
const xex_header = @import("../xex/header.zig");
const xex_image = @import("../xex/image.zig");
const manifest = @import("manifest.zig");
const parse = @import("parse.zig");

pub const Options = parse.Extract;

pub const Summary = struct {
    files: u32,
    bytes: u64,
    skipped: u32,
    xex_version: [4]u16,
    image_verified: bool,
};

/// Title-update images start at 0.0.8.0. The pilot disc is 0.0.0.5.
pub const title_update_threshold: u32 = 0x00000800;

const copy_chunk: usize = 1 << 20;

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !Summary {
    var src = try iso_mod.Iso.open(io, opts.iso);
    defer src.close(io);

    const vol = try xdvdfs.open(iso_mod.Iso, &src, io);
    const entries = try vol.walk(allocator, iso_mod.Iso, &src, io);
    defer xdvdfs.freeEntries(allocator, entries);
    std.mem.sort(xdvdfs.Entry, entries, {}, entryLessThan);

    const xex_entry = findEntry(entries, "default.xex") orelse return error.MissingDefaultXex;

    const head_len: usize = @min(@as(usize, xex_entry.size), 1 << 20);
    const head = try allocator.alloc(u8, head_len);
    defer allocator.free(head);
    try src.readAt(io, vol.base + @as(u64, xex_entry.sector) * xdvdfs.SECTOR, head);

    var h = try xex_header.parse(allocator, head);
    defer h.deinit(allocator);

    const version = h.execution.version;
    if (version.value >= title_update_threshold) return error.TitleUpdateRejected;

    var image_verified = false;
    var image_sha256: ?[manifest.digest_hex_len]u8 = null;

    if (key) |supplied_key| {
        const xex_bytes = try allocator.alloc(u8, xex_entry.size);
        defer allocator.free(xex_bytes);
        try src.readAt(io, vol.base + @as(u64, xex_entry.sector) * xdvdfs.SECTOR, xex_bytes);

        var img = try xex_image.loadBytes(allocator, xex_bytes, supplied_key);
        defer img.deinit(allocator);

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(img.bytes, &digest, .{});
        var hex: [manifest.digest_hex_len]u8 = undefined;
        manifest.hexLower(&digest, &hex);
        image_sha256 = hex;
        image_verified = true;
    }

    var out_dir = try Io.Dir.cwd().createDirPathOpen(io, opts.out, .{ .open_options = .{ .iterate = true } });
    defer out_dir.close(io);

    var existing: ?manifest.Manifest = manifest.read(allocator, io, opts.out) catch |e| switch (e) {
        error.ManifestNotFound => null,
        error.CorruptManifest => return error.ExistingManifestCorrupt,
        error.UnsupportedAbi => return error.ExistingManifestCorrupt,
        else => |other| return other,
    };
    defer if (existing) |*m| m.deinit(allocator);

    const xex_version = [4]u16{ version.major(), version.minor(), version.build(), version.qfe() };
    // WORKAROUND: a modified disc with the same title, version and size still
    // reuses the manifest. Add an ISO fingerprint when that case matters.
    // Triggers on every extract rerun with a matching manifest.
    const stale = if (existing) |m|
        m.iso_size != src.size or m.title_id != h.execution.title_id or !std.mem.eql(u16, &m.xex_version, &xex_version)
    else
        false;

    if (existing == null) {
        var it = out_dir.iterate();
        if (try it.next(io) != null) return error.OutDirNotEmpty;
    }

    const digests = try allocator.alloc([manifest.digest_hex_len]u8, entries.len);
    defer allocator.free(digests);

    var summary = Summary{
        .files = @intCast(entries.len),
        .bytes = 0,
        .skipped = 0,
        .xex_version = xex_version,
        .image_verified = image_verified,
    };

    for (entries, 0..) |entry, i| {
        if (!stale) {
            if (existing) |m| {
                if (m.find(entry.path)) |old| {
                    var current_hex: [manifest.digest_hex_len]u8 = undefined;
                    var current_size: u64 = 0;
                    const present = try hashExisting(io, out_dir, entry.path, &current_hex, &current_size);
                    if (present and current_size == entry.size and std.mem.eql(u8, &old.sha256, &current_hex)) {
                        digests[i] = current_hex;
                        summary.skipped += 1;
                        continue;
                    }
                }
            }
        }

        digests[i] = try copyEntry(allocator, io, &src, vol, entry, out_dir);
        summary.bytes += entry.size;
    }

    const manifest_entries = try allocator.alloc(manifest.Entry, entries.len);
    defer allocator.free(manifest_entries);
    for (entries, 0..) |entry, i| {
        manifest_entries[i] = .{ .path = entry.path, .size = entry.size, .sha256 = digests[i] };
    }

    const m = manifest.Manifest{
        .iso_size = src.size,
        .disc_base = vol.base,
        .xex_version = summary.xex_version,
        .title_id = h.execution.title_id,
        .image_size = h.security.image_size,
        .image_verified = image_verified,
        .image_sha256 = image_sha256,
        .entries = manifest_entries,
    };
    try manifest.write(allocator, io, opts.out, &m);

    return summary;
}

fn entryLessThan(_: void, a: xdvdfs.Entry, b: xdvdfs.Entry) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

fn findEntry(entries: []const xdvdfs.Entry, path: []const u8) ?xdvdfs.Entry {
    for (entries) |e| {
        if (std.mem.eql(u8, e.path, path)) return e;
    }
    return null;
}

fn hashExisting(
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    out_hex: *[manifest.digest_hex_len]u8,
    out_size: *u64,
) !bool {
    const file = dir.openFile(io, path, .{}) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => |other| return other,
    };
    defer file.close(io);

    const st = try file.stat(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [copy_chunk]u8 = undefined;
    var offset: u64 = 0;
    while (offset < st.size) {
        const n = @min(buf.len, st.size - offset);
        if (try file.readPositionalAll(io, buf[0..n], offset) != n) return error.Truncated;
        hasher.update(buf[0..n]);
        offset += n;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    manifest.hexLower(&digest, out_hex);
    out_size.* = st.size;
    return true;
}

fn copyEntry(
    allocator: std.mem.Allocator,
    io: Io,
    src: *iso_mod.Iso,
    vol: xdvdfs.Volume,
    entry: xdvdfs.Entry,
    dir: Io.Dir,
) ![manifest.digest_hex_len]u8 {
    const buf = try allocator.alloc(u8, copy_chunk);
    defer allocator.free(buf);

    var atomic = try dir.createFileAtomic(io, entry.path, .{ .replace = true, .make_path = true });
    defer atomic.deinit(io);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const base = vol.base + @as(u64, entry.sector) * xdvdfs.SECTOR;
    var offset: u64 = 0;
    while (offset < entry.size) {
        const n = @min(buf.len, entry.size - offset);
        try src.readAt(io, base + offset, buf[0..n]);
        hasher.update(buf[0..n]);
        try atomic.file.writePositionalAll(io, buf[0..n], offset);
        offset += n;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var hex: [manifest.digest_hex_len]u8 = undefined;
    manifest.hexLower(&digest, &hex);

    try atomic.replace(io);

    const st = try dir.statFile(io, entry.path, .{});
    if (st.size != entry.size) return error.SizeMismatch;

    return hex;
}

const testing = std.testing;
const iso_writer = @import("../disc/iso_writer.zig");
const xex_writer = @import("../xex/xex_writer.zig");

fn tmpPath(tmp: *testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

fn testIo() Io {
    return Io.Threaded.global_single_threaded.io();
}

fn setupIso(io: Io, tmp: *testing.TmpDir, xex: []const u8, path_buf: []u8) ![]const u8 {
    var img = try iso_writer.buildWithXex(testing.allocator, 0, xex);
    defer img.deinit(testing.allocator);
    try tmp.dir.writeFile(io, .{ .sub_path = "disc.iso", .data = img.bytes });
    return tmpPath(tmp, path_buf, "disc.iso");
}

test "extract writes the tree and manifest without a key" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    const summary = try run(testing.allocator, io, .{ .iso = iso_path, .out = out_path, .key = null }, null);
    try testing.expectEqual(@as(u32, 3), summary.files);
    try testing.expectEqual(@as(u32, 0), summary.skipped);
    try testing.expectEqual(false, summary.image_verified);
    try testing.expectEqual([4]u16{ 0, 0, 0, 5 }, summary.xex_version);

    var m = try manifest.read(testing.allocator, io, out_path);
    defer m.deinit(testing.allocator);
    try testing.expectEqual(false, m.image_verified);
    try testing.expectEqual(@as(u64, 0), m.disc_base);
    try testing.expectEqual(@as(usize, 3), m.entries.len);

    var out_dir = try Io.Dir.cwd().openDir(io, out_path, .{});
    defer out_dir.close(io);
    const got = try out_dir.readFileAlloc(io, "default.xex", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, xex, got);
}

test "second extract skips every file" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    const first = try run(testing.allocator, io, .{ .iso = iso_path, .out = out_path, .key = null }, null);
    const second = try run(testing.allocator, io, .{ .iso = iso_path, .out = out_path, .key = null }, null);
    try testing.expectEqual(@as(u32, 0), first.skipped);
    try testing.expectEqual(@as(u32, 3), second.skipped);
    try testing.expectEqual(@as(u64, 0), second.bytes);
}

test "a different title rewrites the whole tree" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex_a = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex_a);
    const xex_b = try testing.allocator.dupe(u8, xex_a);
    defer testing.allocator.free(xex_b);
    std.mem.writeInt(u32, xex_b[xex_writer.off.execution + 0x0C ..][0..4], 0x11111111, .big);

    var img_a = try iso_writer.buildWithXex(testing.allocator, 0, xex_a);
    defer img_a.deinit(testing.allocator);
    var img_b = try iso_writer.buildWithXex(testing.allocator, 0, xex_b);
    defer img_b.deinit(testing.allocator);
    img_b.bytes[44 * iso_writer.SECTOR] ^= 0xFF;

    try tmp.dir.writeFile(io, .{ .sub_path = "a.iso", .data = img_a.bytes });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.iso", .data = img_b.bytes });
    var a_buf: [256]u8 = undefined;
    var b_buf: [256]u8 = undefined;
    const a_path = try tmpPath(&tmp, &a_buf, "a.iso");
    const b_path = try tmpPath(&tmp, &b_buf, "b.iso");
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    _ = try run(testing.allocator, io, .{ .iso = a_path, .out = out_path, .key = null }, null);
    const second = try run(testing.allocator, io, .{ .iso = b_path, .out = out_path, .key = null }, null);
    try testing.expectEqual(@as(u32, 0), second.skipped);

    var out_dir = try Io.Dir.cwd().openDir(io, out_path, .{});
    defer out_dir.close(io);
    const got = try out_dir.readFileAlloc(io, "common.rpf", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, img_b.bytes[44 * iso_writer.SECTOR ..][0..4096], got);
}

test "a corrupted file is rewritten" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    _ = try run(testing.allocator, io, .{ .iso = iso_path, .out = out_path, .key = null }, null);

    const junk = try testing.allocator.alloc(u8, 4096);
    defer testing.allocator.free(junk);
    @memset(junk, 0xAA);
    var out_dir = try Io.Dir.cwd().openDir(io, out_path, .{});
    defer out_dir.close(io);
    try out_dir.writeFile(io, .{ .sub_path = "common.rpf", .data = junk });

    const second = try run(testing.allocator, io, .{ .iso = iso_path, .out = out_path, .key = null }, null);
    try testing.expectEqual(@as(u32, 2), second.skipped);
    try testing.expectEqual(@as(u64, 4096), second.bytes);
}

test "wrong key is wrong key and writes nothing" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 1, 1);
    defer testing.allocator.free(xex);
    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    const wrong_key: [16]u8 = @splat(0);
    try testing.expectError(error.WrongKey, run(testing.allocator, io, .{
        .iso = iso_path,
        .out = out_path,
        .key = null,
    }, wrong_key));
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().openDir(io, out_path, .{}));
}

test "title update version is rejected" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    std.mem.writeInt(u32, xex[xex_writer.off.execution + 4 ..][0..4], 0x00000800, .big);

    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    try testing.expectError(error.TitleUpdateRejected, run(testing.allocator, io, .{
        .iso = iso_path,
        .out = out_path,
        .key = null,
    }, null));
}

test "foreign output directory is refused" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    var out_dir = try Io.Dir.cwd().createDirPathOpen(io, out_path, .{});
    defer out_dir.close(io);
    try out_dir.writeFile(io, .{ .sub_path = "user-file.txt", .data = "mine" });

    try testing.expectError(error.OutDirNotEmpty, run(testing.allocator, io, .{
        .iso = iso_path,
        .out = out_path,
        .key = null,
    }, null));
}

test "title update rejection creates no tree" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const xex = try xex_writer.buildFull(testing.allocator, 0, 1);
    defer testing.allocator.free(xex);
    std.mem.writeInt(u32, xex[xex_writer.off.execution + 4 ..][0..4], 0x00000800, .big);

    var iso_buf: [256]u8 = undefined;
    const iso_path = try setupIso(io, &tmp, xex, &iso_buf);
    var out_buf: [256]u8 = undefined;
    const out_path = try tmpPath(&tmp, &out_buf, "out");

    try testing.expectError(error.TitleUpdateRejected, run(testing.allocator, io, .{
        .iso = iso_path,
        .out = out_path,
        .key = null,
    }, null));
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().openDir(io, out_path, .{}));
}
