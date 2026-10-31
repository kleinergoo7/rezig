//! `rezig analyze`: report an XEX or ELF header, entry point and sections.

const std = @import("std");
const Io = std.Io;
const input = @import("input.zig");
const parse = @import("parse.zig");

pub const Options = parse.Analyze;

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    var loaded = try input.load(allocator, io, opts.tree, opts.xex, opts.elf, key);
    defer loaded.deinit(allocator);
    const img = &loaded.image;

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    if (opts.tree) |tree| {
        try out.print("tree: {s}\n", .{tree});
    } else if (opts.elf) |path| {
        try out.print("elf: {s}\n", .{path});
    } else {
        try out.print("xex: {s}\n", .{opts.xex.?});
    }
    try out.print("version {d}.{d}.{d}.{d}, title {X:0>8}\n", .{
        img.version.major(),
        img.version.minor(),
        img.version.build(),
        img.version.qfe(),
        img.title_id,
    });
    try out.print("image: base 0x{X:0>8}, entry 0x{X:0>8}, size 0x{X:0>8}\n", .{
        img.base_address,
        img.entry_point,
        img.bytes.len,
    });

    for (img.sections, 0..) |section, i| {
        const name_len = std.mem.indexOfScalar(u8, &section.name, 0) orelse section.name.len;
        try out.print("section {d}: {s} rva 0x{X:0>8} size 0x{X:0>8}{s}\n", .{
            i,
            section.name[0..name_len],
            section.virtual_address,
            section.virtual_size,
            if (img.isExecutable(section)) " exec" else "",
        });
    }

    try out.flush();
}
