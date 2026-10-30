//! XDVDFS volume and directory parsing.
//!
//! Format facts come from the pilot discs: 2048-byte sectors, volume descriptor at
//! sector 32 of the game partition, little-endian fields, 14-byte directory records.

const std = @import("std");
const Io = std.Io;

pub const SECTOR: u32 = 2048;
pub const VOLUME_SECTOR: u32 = 32;
pub const XGD2_BASE: u64 = 0xFD90000;
pub const MAGIC = "MICROSOFT*XBOX*MEDIA";
pub const NONE: u16 = 0xffff;
pub const MAX_DEPTH: u8 = 32;
pub const MAX_ENTRIES: u32 = 1_000_000;
pub const MAX_PATH: usize = 1024;
pub const MAX_DIR_BYTES: u32 = 1 << 20;

pub const Error = error{
    NotXdvdfs,
    Truncated,
    EntryOutOfRange,
    TooManyEntries,
    DirectoryCycle,
    DuplicatePath,
    PathTooLong,
    TooDeep,
    NotFound,
    AccessDenied,
    FileNotFound,
    OutOfMemory,
};

pub const Entry = struct {
    path: []u8,
    sector: u32,
    size: u32,
};

pub const Volume = struct {
    base: u64,
    image_size: u32,
    root_sector: u32,
    root_size: u32,

    pub fn walk(
        self: *const Volume,
        allocator: std.mem.Allocator,
        comptime S: type,
        src: *S,
        io: Io,
    ) Error![]Entry {
        var walker = Walker(S){
            .allocator = allocator,
            .io = io,
            .vol = self,
            .src = src,
        };
        defer walker.deinit();

        try walker.walkTable(self.root_sector, self.root_size, "", 0);

        const entries = try walker.entries.toOwnedSlice(allocator);
        walker.entries = .empty;
        return entries;
    }

    fn checkRange(self: *const Volume, sector: u32, size: u32) Error!void {
        const start = @as(u64, sector) * SECTOR;
        if (start + size > self.image_size) return error.EntryOutOfRange;
    }

    pub fn readFile(
        self: *const Volume,
        allocator: std.mem.Allocator,
        comptime S: type,
        src: *S,
        io: Io,
        path: []const u8,
    ) Error![]u8 {
        const entries = try self.walk(allocator, S, src, io);
        defer freeEntries(allocator, entries);

        for (entries) |e| {
            if (!std.mem.eql(u8, e.path, path)) continue;
            const bytes = try allocator.alloc(u8, e.size);
            errdefer allocator.free(bytes);
            try src.readAt(io, self.base + @as(u64, e.sector) * SECTOR, bytes);
            return bytes;
        }
        return error.NotFound;
    }
};

pub fn detectBase(comptime S: type, src: *S, io: Io) Error!u64 {
    var magic: [MAGIC.len]u8 = undefined;
    for ([_]u64{ 0, XGD2_BASE }) |base| {
        src.readAt(io, base + VOLUME_SECTOR * SECTOR, &magic) catch |e| switch (e) {
            error.Truncated => continue,
            else => |other| return other,
        };
        if (std.mem.eql(u8, &magic, MAGIC)) return base;
    }
    return error.NotXdvdfs;
}

pub fn open(comptime S: type, src: *S, io: Io) Error!Volume {
    const base = try detectBase(S, src, io);
    if (base > src.size) return error.Truncated;

    var vd: [SECTOR]u8 = undefined;
    try src.readAt(io, base + VOLUME_SECTOR * SECTOR, &vd);

    const root_sector = std.mem.readInt(u32, vd[0x14..][0..4], .little);
    const root_size = std.mem.readInt(u32, vd[0x18..][0..4], .little);
    const image_size = std.mem.readInt(u32, vd[0x1C..][0..4], .little);

    if (root_sector == 0 or root_size == 0) return error.NotXdvdfs;
    if (root_size % SECTOR != 0) return error.NotXdvdfs;
    if (root_size > MAX_DIR_BYTES) return error.EntryOutOfRange;
    if (image_size > src.size - base) return error.Truncated;

    const vol = Volume{
        .base = base,
        .image_size = image_size,
        .root_sector = root_sector,
        .root_size = root_size,
    };
    try vol.checkRange(root_sector, root_size);
    return vol;
}

pub fn freeEntries(allocator: std.mem.Allocator, entries: []Entry) void {
    for (entries) |e| allocator.free(e.path);
    allocator.free(entries);
}

fn Walker(comptime S: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        io: Io,
        vol: *const Volume,
        src: *S,
        entries: std.ArrayList(Entry) = .empty,
        seen_dirs: std.AutoHashMapUnmanaged(u32, void) = .empty,
        seen_paths: std.StringHashMapUnmanaged(void) = .empty,
        count: u32 = 0,

        fn deinit(self: *Self) void {
            for (self.entries.items) |e| self.allocator.free(e.path);
            self.seen_dirs.deinit(self.allocator);
            self.seen_paths.deinit(self.allocator);
            self.entries.deinit(self.allocator);
        }

        fn walkTable(
            self: *Self,
            sector: u32,
            size: u32,
            prefix: []const u8,
            depth: u8,
        ) Error!void {
            if (depth > MAX_DEPTH) return error.TooDeep;
            try self.vol.checkRange(sector, size);

            const gop = try self.seen_dirs.getOrPut(self.allocator, sector);
            if (gop.found_existing) return error.DirectoryCycle;

            const table = try self.allocator.alloc(u8, size);
            defer self.allocator.free(table);
            try self.src.readAt(self.io, self.vol.base + @as(u64, sector) * SECTOR, table);

            var seen_nodes: std.AutoHashMapUnmanaged(u32, void) = .empty;
            defer seen_nodes.deinit(self.allocator);

            try self.walkNode(table, 0, prefix, depth, &seen_nodes);
        }

        fn walkNode(
            self: *Self,
            table: []const u8,
            start: u32,
            prefix: []const u8,
            depth: u8,
            seen_nodes: *std.AutoHashMapUnmanaged(u32, void),
        ) Error!void {
            var offset = start;
            while (offset != NONE) {
                if (@as(usize, offset) + 14 > table.len) return error.Truncated;

                const gop = try seen_nodes.getOrPut(self.allocator, offset);
                if (gop.found_existing) return error.DirectoryCycle;

                const rec = table[offset..];
                const left = std.mem.readInt(u16, rec[0..2], .little);
                const right = std.mem.readInt(u16, rec[2..4], .little);
                const sector = std.mem.readInt(u32, rec[4..8], .little);
                const size = std.mem.readInt(u32, rec[8..12], .little);
                const attr = rec[12];
                const name_len = rec[13];

                if (name_len == 0) return error.NotXdvdfs;
                if (@as(usize, offset) + 14 + name_len > table.len) return error.Truncated;
                const name = rec[14..][0..name_len];

                if (attr & 0x10 != 0) {
                    try self.checkDirEntry(sector, size);
                    const child_prefix = try self.joinPath(prefix, name);
                    defer if (child_prefix.len != 0) self.allocator.free(child_prefix);
                    try self.walkTable(sector, size, child_prefix, depth + 1);
                } else {
                    try self.vol.checkRange(sector, size);
                    try self.addFile(prefix, name, sector, size);
                }

                if (left != NONE) try self.walkNode(table, left, prefix, depth, seen_nodes);
                offset = right;
            }
        }

        fn checkDirEntry(self: *Self, sector: u32, size: u32) Error!void {
            if (sector == 0 or size == 0) return error.NotXdvdfs;
            if (size % SECTOR != 0 or size > MAX_DIR_BYTES) return error.EntryOutOfRange;
            try self.vol.checkRange(sector, size);
        }

        fn addFile(self: *Self, prefix: []const u8, name: []const u8, sector: u32, size: u32) Error!void {
            self.count += 1;
            if (self.count > MAX_ENTRIES) return error.TooManyEntries;

            const path = try self.joinPath(prefix, name);
            errdefer self.allocator.free(path);

            const gop = try self.seen_paths.getOrPut(self.allocator, path);
            if (gop.found_existing) return error.DuplicatePath;

            try self.entries.append(self.allocator, .{ .path = path, .sector = sector, .size = size });
        }

        fn joinPath(self: *Self, prefix: []const u8, name: []const u8) Error![]u8 {
            const len = prefix.len + @as(usize, if (prefix.len == 0) 0 else 1) + name.len;
            if (len > MAX_PATH) return error.PathTooLong;
            if (prefix.len == 0) return self.allocator.dupe(u8, name);
            const path = try self.allocator.alloc(u8, len);
            @memcpy(path[0..prefix.len], prefix);
            path[prefix.len] = '/';
            @memcpy(path[prefix.len + 1 ..], name);
            return path;
        }
    };
}

const testing = std.testing;
const iso_writer = @import("../fixtures/iso_writer.zig");

fn testIo() Io {
    return Io.Threaded.global_single_threaded.io();
}

test "detect base zero" {
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), try detectBase(iso_writer.Image, &img, testIo()));
}

test "detect xgd2 base" {
    var img = try iso_writer.build(testing.allocator, XGD2_BASE);
    defer img.deinit(testing.allocator);
    try testing.expectEqual(XGD2_BASE, try detectBase(iso_writer.Image, &img, testIo()));
}

test "missing volume magic is not xdvdfs" {
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);
    @memset(img.bytes[iso_writer.VOLUME_SECTOR * iso_writer.SECTOR ..][0..20], 0);
    try testing.expectError(error.NotXdvdfs, detectBase(iso_writer.Image, &img, testIo()));
    try testing.expectError(error.NotXdvdfs, open(iso_writer.Image, &img, testIo()));
}

test "walk lists files with sizes and normalized paths" {
    const io = testIo();
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);

    const vol = try open(iso_writer.Image, &img, io);
    const entries = try vol.walk(testing.allocator, iso_writer.Image, &img, io);
    defer freeEntries(testing.allocator, entries);

    try testing.expectEqual(@as(usize, 3), entries.len);

    const xex = find(entries, "default.xex").?;
    try testing.expectEqual(iso_writer.XEX_SECTOR, xex.sector);
    try testing.expectEqual(@as(u32, 100), xex.size);

    const rpf = find(entries, "common.rpf").?;
    try testing.expectEqual(@as(u32, 4096), rpf.size);

    const inner = find(entries, "data/inner.bin").?;
    try testing.expectEqual(@as(u32, 7), inner.size);
}

test "readFile returns exact bytes" {
    const io = testIo();
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);

    const vol = try open(iso_writer.Image, &img, io);
    const bytes = try vol.readFile(testing.allocator, iso_writer.Image, &img, io, "data/inner.bin");
    defer testing.allocator.free(bytes);

    try testing.expectEqual(@as(usize, 7), bytes.len);
    for (bytes, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(3 +% @as(u8, @truncate(i)))), b);
}

test "entry past the image is rejected" {
    const io = testIo();
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);

    // Point default.xex's record at a sector beyond the volume image size.
    const root = img.bytes[iso_writer.ROOT_SECTOR * iso_writer.SECTOR ..];
    std.mem.writeInt(u32, root[24..][0..4], 200, .little);

    const vol = try open(iso_writer.Image, &img, io);
    try testing.expectError(error.EntryOutOfRange, vol.walk(testing.allocator, iso_writer.Image, &img, io));
}

test "directory linking back to its ancestor is rejected" {
    const io = testIo();
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);

    const root = img.bytes[iso_writer.ROOT_SECTOR * iso_writer.SECTOR ..];
    std.mem.writeInt(u32, root[4..][0..4], iso_writer.ROOT_SECTOR, .little);

    const vol = try open(iso_writer.Image, &img, io);
    try testing.expectError(error.DirectoryCycle, vol.walk(testing.allocator, iso_writer.Image, &img, io));
}

test "deep nesting is rejected" {
    const io = testIo();
    var img = try iso_writer.buildDeep(testing.allocator, 0, 40);
    defer img.deinit(testing.allocator);

    const vol = try open(iso_writer.Image, &img, io);
    try testing.expectError(error.TooDeep, vol.walk(testing.allocator, iso_writer.Image, &img, io));
}

test "read past the source is truncated" {
    var img = try iso_writer.build(testing.allocator, 0);
    defer img.deinit(testing.allocator);
    var buf: [1]u8 = undefined;
    try testing.expectError(error.Truncated, img.readAt(testIo(), img.size, &buf));
}

fn find(entries: []const Entry, path: []const u8) ?Entry {
    for (entries) |e| {
        if (std.mem.eql(u8, e.path, path)) return e;
    }
    return null;
}
