//! Public CLI surface for rezig.

const std = @import("std");
const Io = std.Io;

pub const usage =
    \\usage: rezig <command> [options]
    \\
    \\commands:
    \\  extract   Copy the disc tree from an ISO and verify it
    \\  analyze   Parse the XEX and report version, entry point and sections
    \\  codegen   Emit Zig source for selected guest functions
    \\  build     Build the generated project
    \\  run       Run the generated project
    \\  help      Show this message
    \\
;

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const [:0]const u8) !u8 {
    _ = gpa;
    var buf: [1024]u8 = undefined;
    var writer = Io.File.stderr().writer(io, &buf);

    if (args.len < 2) {
        try writer.interface.writeAll(usage);
        try writer.interface.flush();
        return 2;
    }

    try writer.interface.print("rezig: unknown command '{s}'\n", .{args[1]});
    try writer.interface.writeAll(usage);
    try writer.interface.flush();
    return 2;
}

test "no arguments prints usage and exits 2" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 2), try run(std.testing.allocator, io, &.{"rezig"}));
}
