//! `rezig analyze`: decrypt the XEX and report its version, entry point and PE sections.

const std = @import("std");
const Io = std.Io;
const xex_image = @import("../xex/image.zig");
const parse = @import("parse.zig");

pub const Options = parse.Analyze;

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    const xex_path = if (opts.xex) |path|
        try allocator.dupe(u8, path)
    else
        try std.fmt.allocPrint(allocator, "{s}/default.xex", .{opts.tree.?});
    defer allocator.free(xex_path);

    var img = try xex_image.load(allocator, io, xex_path, key);
    defer img.deinit(allocator);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    if (opts.tree) |tree| {
        try out.print("tree: {s}\n", .{tree});
    } else {
        try out.print("xex: {s}\n", .{xex_path});
    }
    try out.print("xex: version {d}.{d}.{d}.{d}, title {X:0>8}\n", .{
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
