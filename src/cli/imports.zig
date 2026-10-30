//! `rezig imports`: list the XEX import libraries and their thunk addresses.

const std = @import("std");
const Io = std.Io;
const xextool = @import("xextool");
const parse = @import("parse.zig");

pub const Options = parse.Analyze;

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    const xex_path = if (opts.xex) |p|
        try allocator.dupe(u8, p)
    else
        try std.fmt.allocPrint(allocator, "{s}/default.xex", .{opts.tree.?});
    defer allocator.free(xex_path);

    const bytes = try Io.Dir.cwd().readFileAlloc(io, xex_path, allocator, .limited(1 << 40));
    defer allocator.free(bytes);

    // Import tables live in the unencrypted header, so a key is only needed
    // when the image itself is encrypted.
    const keys = xextool.xex.keys.Keys.uniform(key orelse std.mem.zeroes([16]u8));

    var xex = xextool.xex.model.Xex.init(allocator);
    defer xex.deinit();

    _ = try xextool.xex.reader.readBytes(&xex, bytes, keys);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    try out.print("imports: {d} libraries\n", .{xex.import_libraries.items.len});
    for (xex.import_libraries.items) |lib| {
        const name = std.mem.sliceTo(&lib.name, 0);
        try out.print("  {s} (module {d}, version {d}.{d}, {d} thunks)\n", .{
            name,
            lib.module_number,
            lib.version >> 16,
            lib.version & 0xffff,
            lib.addresses.len / 2,
        });
        for (lib.addresses, 0..) |addr, i| {
            if (i < 4 or i + 1 == lib.addresses.len) {
                try out.print("    0x{X:0>8}\n", .{addr});
            } else if (i == 4) {
                try out.print("    ...\n", .{});
            }
        }
    }
    try out.flush();
}
