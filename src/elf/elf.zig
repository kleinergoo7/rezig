//! ELF32 big-endian PowerPC loader for homebrew Xbox 360 images.
//!
//! The output uses the same `Image` shape as the XEX loader so coverage and
//! codegen can consume either format.

const std = @import("std");
const Io = std.Io;
const image = @import("../xex/image.zig");

pub const MAX_IMAGE: u32 = 0x4000_0000;
pub const MAX_FILE: u64 = 0x8000_0000;

pub const Error = error{
    NotElf,
    NotElf32,
    NotBigEndian,
    NotPowerPc,
    Truncated,
    BadProgramHeaders,
    BadSectionHeaders,
    TooLarge,
} || std.mem.Allocator.Error;

pub const SHT_NOBITS: u32 = 8;
pub const SHF_ALLOC: u32 = 0x2;
pub const SHF_EXECINSTR: u32 = 0x4;
pub const PT_LOAD: u32 = 1;

const Header = struct {
    entry: u32,
    phoff: u32,
    shoff: u32,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};

const Section = struct {
    name: []const u8,
    virtual_address: u32,
    virtual_size: u32,
    file_offset: u32,
    file_size: u32,
    flags: u32,
    kind: u32,
};

pub fn load(allocator: std.mem.Allocator, io: Io, path: []const u8) !image.Image {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(MAX_FILE));
    defer allocator.free(bytes);
    return loadBytes(allocator, bytes);
}

pub fn loadBytes(allocator: std.mem.Allocator, bytes: []const u8) Error!image.Image {
    const h = try parseHeader(bytes);
    if (h.phnum == 0 or h.phentsize < 32) return error.BadProgramHeaders;
    if (@as(u64, h.phoff) + @as(u64, h.phnum) * h.phentsize > bytes.len) return error.Truncated;

    var image_size: u32 = 0;
    var i: u16 = 0;
    while (i < h.phnum) : (i += 1) {
        const at = h.phoff + @as(u32, i) * h.phentsize;
        if (readU32(bytes, at) != PT_LOAD) continue;
        const offset = readU32(bytes, at + 4);
        const vaddr = readU32(bytes, at + 8);
        const file_size = readU32(bytes, at + 16);
        const mem_size = readU32(bytes, at + 20);
        if (@as(u64, offset) + file_size > bytes.len) return error.Truncated;
        if (file_size > mem_size) return error.BadProgramHeaders;
        const end = @as(u64, vaddr) + mem_size;
        if (end > MAX_IMAGE) return error.TooLarge;
        image_size = @max(image_size, @as(u32, @intCast(end)));
    }
    if (image_size == 0) return error.BadProgramHeaders;

    const img = try allocator.alloc(u8, image_size);
    errdefer allocator.free(img);
    @memset(img, 0);

    i = 0;
    while (i < h.phnum) : (i += 1) {
        const at = h.phoff + @as(u32, i) * h.phentsize;
        if (readU32(bytes, at) != PT_LOAD) continue;
        const offset = readU32(bytes, at + 4);
        const vaddr = readU32(bytes, at + 8);
        const file_size = readU32(bytes, at + 16);
        @memcpy(img[vaddr..][0..file_size], bytes[offset..][0..file_size]);
    }

    const sections = try loadSections(allocator, bytes, h);
    errdefer allocator.free(sections);

    return .{
        .bytes = img,
        .base_address = 0,
        .entry_point = h.entry,
        .size_of_image = image_size,
        .sections = sections,
        .version = .{ .value = 0 },
        .title_id = 0,
        .media_id = 0,
    };
}

/// Function starts from the `.eh_frame_hdr` binary search table. The table
/// encoding used by libxenon is sdata4 + datarel.
pub fn functionSeeds(allocator: std.mem.Allocator, bytes: []const u8) Error![]u32 {
    const h = try parseHeader(bytes);
    if (h.shnum == 0 or h.shentsize < 40) return &.{};
    if (@as(u64, h.shoff) + @as(u64, h.shnum) * h.shentsize > bytes.len) return error.Truncated;

    const sections = try parseSections(allocator, bytes, h);
    defer allocator.free(sections);

    for (sections) |s| {
        if (!std.mem.eql(u8, s.name, ".eh_frame_hdr")) continue;
        if (s.kind == SHT_NOBITS or s.file_size < 12) return &.{};
        if (@as(u64, s.file_offset) + s.file_size > bytes.len) return error.Truncated;
        const hdr = bytes[s.file_offset..][0..s.file_size];
        if (hdr[0] != 1 or hdr[1] != 0x1b or hdr[2] != 0x03 or hdr[3] != 0x3b) return &.{};
        const count = readU32(hdr, 8);
        const available = (hdr.len - 12) / 8;
        const n: u32 = @intCast(@min(count, available));
        const seeds = try allocator.alloc(u32, n);
        errdefer allocator.free(seeds);
        for (0..n) |entry| {
            const rel: i32 = @bitCast(readU32(hdr, 12 + @as(u32, @intCast(entry)) * 8));
            seeds[entry] = s.virtual_address +% @as(u32, @bitCast(rel));
        }
        return seeds;
    }
    return &.{};
}

fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < 52) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.NotElf;
    if (bytes[4] != 1) return error.NotElf32;
    if (bytes[5] != 2) return error.NotBigEndian;
    if (readU16(bytes, 18) != 20) return error.NotPowerPc;
    return .{
        .entry = readU32(bytes, 24),
        .phoff = readU32(bytes, 28),
        .shoff = readU32(bytes, 32),
        .phentsize = readU16(bytes, 42),
        .phnum = readU16(bytes, 44),
        .shentsize = readU16(bytes, 46),
        .shnum = readU16(bytes, 48),
        .shstrndx = readU16(bytes, 50),
    };
}

fn parseSections(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    h: Header,
) Error![]Section {
    if (h.shnum == 0 or h.shentsize < 40) return &.{};
    if (@as(u64, h.shoff) + @as(u64, h.shnum) * h.shentsize > bytes.len) return error.Truncated;
    if (h.shstrndx >= h.shnum) return error.BadSectionHeaders;

    const str_header = h.shoff + @as(u32, h.shstrndx) * h.shentsize;
    const str_offset = readU32(bytes, str_header + 16);
    const str_size = readU32(bytes, str_header + 20);
    if (@as(u64, str_offset) + str_size > bytes.len) return error.Truncated;
    const strtab = bytes[str_offset..][0..str_size];

    var list: std.ArrayList(Section) = .empty;
    errdefer list.deinit(allocator);
    var i: u16 = 0;
    while (i < h.shnum) : (i += 1) {
        const at = h.shoff + @as(u32, i) * h.shentsize;
        const name_offset = readU32(bytes, at);
        const name = if (name_offset < strtab.len)
            strtab[name_offset..][0..strIndex(strtab[name_offset..])]
        else
            "";
        const kind = readU32(bytes, at + 4);
        const flags = readU32(bytes, at + 8);
        const addr = readU32(bytes, at + 12);
        const offset = readU32(bytes, at + 16);
        const size = readU32(bytes, at + 20);
        if (flags & SHF_ALLOC == 0) continue;
        if (kind == SHT_NOBITS) {
            try list.append(allocator, .{
                .name = name,
                .virtual_address = addr,
                .virtual_size = size,
                .file_offset = offset,
                .file_size = 0,
                .flags = flags,
                .kind = kind,
            });
        } else {
            if (@as(u64, offset) + size > bytes.len) return error.Truncated;
            try list.append(allocator, .{
                .name = name,
                .virtual_address = addr,
                .virtual_size = size,
                .file_offset = offset,
                .file_size = size,
                .flags = flags,
                .kind = kind,
            });
        }
    }
    return list.toOwnedSlice(allocator);
}

fn loadSections(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    h: Header,
) Error![]image.PeSection {
    const sections = try parseSections(allocator, bytes, h);
    defer allocator.free(sections);
    const out = try allocator.alloc(image.PeSection, sections.len);
    errdefer allocator.free(out);

    for (sections, 0..) |s, i| {
        var name: [8]u8 = @splat(0);
        const n = @min(s.name.len, name.len);
        @memcpy(name[0..n], s.name[0..n]);
        out[i] = .{
            .name = name,
            .virtual_address = s.virtual_address,
            .virtual_size = s.virtual_size,
            .raw_offset = s.file_offset,
            .raw_size = s.file_size,
            .characteristics = if (s.flags & SHF_EXECINSTR != 0) 0x2000_0000 else 0,
        };
    }
    return out;
}

fn strIndex(s: []const u8) usize {
    return std.mem.indexOfScalar(u8, s, 0) orelse s.len;
}

fn readU16(bytes: []const u8, at: u32) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .big);
}

fn readU32(bytes: []const u8, at: u32) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .big);
}

const testing = std.testing;

fn put16(bytes: []u8, at: u32, value: u16) void {
    std.mem.writeInt(u16, bytes[at..][0..2], value, .big);
}

fn put32(bytes: []u8, at: u32, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .big);
}

fn testElf(allocator: std.mem.Allocator) ![]u8 {
    const bytes = try allocator.alloc(u8, 0x500);
    @memset(bytes, 0);

    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 1; // ELF32
    bytes[5] = 2; // big endian
    bytes[6] = 1;
    put16(bytes, 16, 2); // ET_EXEC
    put16(bytes, 18, 20); // EM_PPC
    put32(bytes, 20, 1);
    put32(bytes, 24, 0x10); // entry
    put32(bytes, 28, 52); // phoff
    put32(bytes, 32, 0x200); // shoff
    put16(bytes, 40, 52);
    put16(bytes, 42, 32);
    put16(bytes, 44, 1);
    put16(bytes, 46, 40);
    put16(bytes, 48, 4);
    put16(bytes, 50, 3);

    // PT_LOAD: vaddr 0, file 0x40, mem 0x80, RWX.
    put32(bytes, 52, 1);
    put32(bytes, 56, 0x100);
    put32(bytes, 60, 0);
    put32(bytes, 64, 0);
    put32(bytes, 68, 0x40);
    put32(bytes, 72, 0x80);
    put32(bytes, 76, 5);
    put32(bytes, 80, 4);

    // .text bytes at 0x100.
    for (bytes[0x100..0x120], 0..) |*b, i| b.* = @truncate(i);
    // .eh_frame_hdr at 0x120, vaddr 0x20.
    bytes[0x120] = 1;
    bytes[0x121] = 0x1b;
    bytes[0x122] = 0x03;
    bytes[0x123] = 0x3b;
    put32(bytes, 0x124, 0);
    put32(bytes, 0x128, 1);
    put32(bytes, 0x12c, 0xfffffff0); // datarel -0x10 -> 0x10
    put32(bytes, 0x130, 0);

    // Section name table at 0x400.
    const names = "\x00.text\x00.eh_frame_hdr\x00.shstrtab\x00";
    @memcpy(bytes[0x400..][0..names.len], names);

    // Section headers at 0x200.
    // .text
    put32(bytes, 0x200 + 40, 1); // name
    put32(bytes, 0x200 + 44, 1); // PROGBITS
    put32(bytes, 0x200 + 48, 6); // ALLOC | EXEC
    put32(bytes, 0x200 + 52, 0); // addr
    put32(bytes, 0x200 + 56, 0x100);
    put32(bytes, 0x200 + 60, 0x20);
    // .eh_frame_hdr
    put32(bytes, 0x200 + 80, 7); // name
    put32(bytes, 0x200 + 84, 1);
    put32(bytes, 0x200 + 88, 2);
    put32(bytes, 0x200 + 92, 0x20);
    put32(bytes, 0x200 + 96, 0x120);
    put32(bytes, 0x200 + 100, 20);
    // .shstrtab
    put32(bytes, 0x200 + 120, 22);
    put32(bytes, 0x200 + 124, 3);
    put32(bytes, 0x200 + 128, 0);
    put32(bytes, 0x200 + 136, 0x400);
    put32(bytes, 0x200 + 140, names.len);

    return bytes;
}

test "elf load maps the load segment and sections" {
    const bytes = try testElf(testing.allocator);
    defer testing.allocator.free(bytes);

    var img = try loadBytes(testing.allocator, bytes);
    defer img.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0x80), img.bytes.len);
    try testing.expectEqual(@as(u32, 0x10), img.entry_point);
    try testing.expectEqual(@as(usize, 2), img.sections.len);
    try testing.expectEqualStrings(".text", std.mem.sliceTo(&img.sections[0].name, 0));
    try testing.expect(img.isExecutable(img.sections[0]));
    try testing.expectEqual(@as(usize, 0x20), img.sectionBytes(img.sections[0]).len);
}

test "elf eh_frame_hdr seeds decode datarel entries" {
    const bytes = try testElf(testing.allocator);
    defer testing.allocator.free(bytes);

    const seeds = try functionSeeds(testing.allocator, bytes);
    defer testing.allocator.free(seeds);
    try testing.expectEqualSlices(u32, &.{0x10}, seeds);
}
