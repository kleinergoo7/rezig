//! Common loader for XEX and ELF32 homebrew images.

const std = @import("std");
const Io = std.Io;
const image = @import("../xex/image.zig");
const elf = @import("../elf/elf.zig");
const pdata = @import("../ppc/pdata.zig");

pub const Loaded = struct {
    image: image.Image,
    seeds: []u32,
    is_elf: bool,

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        if (self.seeds.len != 0) allocator.free(self.seeds);
        self.image.deinit(allocator);
        self.* = undefined;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: Io,
    tree: ?[]const u8,
    xex_path: ?[]const u8,
    elf_path: ?[]const u8,
    key: ?[16]u8,
) !Loaded {
    if (elf_path) |path| {
        const bytes = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(elf.MAX_FILE));
        defer allocator.free(bytes);
        var img = try elf.loadBytes(allocator, bytes);
        errdefer img.deinit(allocator);
        const seeds = try elf.functionSeeds(allocator, bytes);
        return .{ .image = img, .seeds = seeds, .is_elf = true };
    }

    const path = if (xex_path) |p|
        try allocator.dupe(u8, p)
    else
        try std.fmt.allocPrint(allocator, "{s}/default.xex", .{tree.?});
    defer allocator.free(path);

    var img = try image.load(allocator, io, path, key);
    errdefer img.deinit(allocator);
    const seeds = try pdataStarts(allocator, &img);
    return .{ .image = img, .seeds = seeds, .is_elf = false };
}

fn pdataStarts(allocator: std.mem.Allocator, img: *const image.Image) ![]u32 {
    for (img.sections) |section| {
        const n = std.mem.indexOfScalar(u8, &section.name, 0) orelse section.name.len;
        if (!std.mem.eql(u8, section.name[0..n], ".pdata")) continue;
        return pdata.starts(allocator, img.sectionBytes(section));
    }
    return &.{};
}
