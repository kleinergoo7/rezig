//! Synthetic XDVDFS images for tests. No game bytes.

const std = @import("std");
const Io = std.Io;

pub const SECTOR = 2048;
pub const VOLUME_SECTOR = 32;
pub const ROOT_SECTOR = 40;
pub const DATA_SECTOR = 41;
pub const XEX_SECTOR = 50;
pub const RPF_SECTOR = 51;
pub const INNER_SECTOR = 53;

pub const magic = "MICROSOFT*XBOX*MEDIA";

pub const Image = struct {
    base: u64,
    bytes: []u8,
    size: u64,

    pub fn deinit(self: *Image, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn readAt(self: *const Image, io: Io, offset: u64, buf: []u8) error{Truncated}!void {
        _ = io;
        if (offset > self.size or buf.len > self.size - offset) return error.Truncated;
        @memset(buf, 0);
        if (offset < self.base) return;
        const rel = offset - self.base;
        if (rel >= self.bytes.len) return;
        const n = @min(buf.len, self.bytes.len - rel);
        @memcpy(buf[0..n], self.bytes[rel..][0..n]);
    }
};

const DirWriter = struct {
    table: []u8,
    cursor: u32 = 0,
    prev: ?u32 = null,

    fn add(self: *DirWriter, name: []const u8, sector: u32, size: u32, attr: u8) void {
        const off = self.cursor;
        const rec = std.mem.alignForward(u32, 14 + @as(u32, @intCast(name.len)), 4);
        std.mem.writeInt(u16, self.table[off..][0..2], 0xffff, .little);
        std.mem.writeInt(u16, self.table[off + 2 ..][0..2], 0xffff, .little);
        std.mem.writeInt(u32, self.table[off + 4 ..][0..4], sector, .little);
        std.mem.writeInt(u32, self.table[off + 8 ..][0..4], size, .little);
        self.table[off + 12] = attr;
        self.table[off + 13] = @intCast(name.len);
        @memcpy(self.table[off + 14 ..][0..name.len], name);
        @memset(self.table[off + 14 + name.len ..][0 .. rec - 14 - name.len], 0);
        // Directory tables are one sector, so a record offset always fits u16.
        if (self.prev) |p| std.mem.writeInt(u16, self.table[p + 2 ..][0..2], @intCast(off), .little);
        self.prev = off;
        self.cursor += rec;
    }
};

pub fn build(allocator: std.mem.Allocator, base: u64) !Image {
    const bytes = try allocator.alloc(u8, 64 * SECTOR);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);

    const vd = bytes[VOLUME_SECTOR * SECTOR ..][0..SECTOR];
    @memcpy(vd[0..magic.len], magic);
    std.mem.writeInt(u32, vd[0x14..][0..4], ROOT_SECTOR, .little);
    std.mem.writeInt(u32, vd[0x18..][0..4], SECTOR, .little);
    std.mem.writeInt(u32, vd[0x1C..][0..4], @intCast(bytes.len), .little);

    var root = DirWriter{ .table = bytes[ROOT_SECTOR * SECTOR ..][0..SECTOR] };
    root.add("data", DATA_SECTOR, SECTOR, 0x10);
    root.add("default.xex", XEX_SECTOR, 100, 0x80);
    root.add("common.rpf", RPF_SECTOR, 4096, 0x80);

    var data = DirWriter{ .table = bytes[DATA_SECTOR * SECTOR ..][0..SECTOR] };
    data.add("inner.bin", INNER_SECTOR, 7, 0x80);

    fillFile(bytes[XEX_SECTOR * SECTOR ..][0..100], 1);
    fillFile(bytes[RPF_SECTOR * SECTOR ..][0..4096], 2);
    fillFile(bytes[INNER_SECTOR * SECTOR ..][0..7], 3);

    return .{ .base = base, .bytes = bytes, .size = base + bytes.len };
}

pub fn buildDeep(allocator: std.mem.Allocator, base: u64, depth: u32) !Image {
    const sectors: u32 = ROOT_SECTOR + depth + 2;
    const bytes = try allocator.alloc(u8, sectors * SECTOR);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);

    const vd = bytes[VOLUME_SECTOR * SECTOR ..][0..SECTOR];
    @memcpy(vd[0..magic.len], magic);
    std.mem.writeInt(u32, vd[0x14..][0..4], ROOT_SECTOR, .little);
    std.mem.writeInt(u32, vd[0x18..][0..4], SECTOR, .little);
    std.mem.writeInt(u32, vd[0x1C..][0..4], @intCast(bytes.len), .little);

    var root = DirWriter{ .table = bytes[ROOT_SECTOR * SECTOR ..][0..SECTOR] };
    root.add("d0", ROOT_SECTOR + 1, SECTOR, 0x10);

    var i: u32 = 0;
    while (i < depth) : (i += 1) {
        const sector = ROOT_SECTOR + 1 + i;
        var dir = DirWriter{ .table = bytes[sector * SECTOR ..][0..SECTOR] };
        if (i + 1 < depth) {
            var name_buf: [8]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "d{d}", .{i + 1});
            dir.add(name, sector + 1, SECTOR, 0x10);
        } else {
            dir.add("leaf.bin", sector + 1, 7, 0x80);
            fillFile(bytes[(sector + 1) * SECTOR ..][0..7], 4);
        }
    }

    return .{ .base = base, .bytes = bytes, .size = base + bytes.len };
}

fn fillFile(dest: []u8, seed: u8) void {
    for (dest, 0..) |*b, i| b.* = @truncate(seed +% @as(u8, @truncate(i)));
}
