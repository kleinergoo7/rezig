//! Public CLI surface for rezig.

const std = @import("std");
const Io = std.Io;
const parse = @import("parse.zig");

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
    const err = &writer.interface;

    const cmd = parse.parse(args) catch |e| {
        switch (e) {
            error.Usage => try err.writeAll(usage),
            error.UnknownCommand => try err.print("rezig: unknown command '{s}'\n{s}", .{ args[1], usage }),
            error.MissingOption => try err.print("rezig: {s}: a required option is missing\n{s}", .{ args[1], usage }),
            error.UnknownOption => try err.print("rezig: {s}: unknown option\n{s}", .{ args[1], usage }),
            error.BadValue => try err.print("rezig: {s}: invalid option value\n{s}", .{ args[1], usage }),
        }
        try err.flush();
        return 2;
    };

    switch (cmd) {
        .help => {
            try err.writeAll(usage);
            try err.flush();
            return 0;
        },
        .extract, .analyze, .codegen, .build, .run => {
            try err.writeAll("rezig: command not implemented yet\n");
            try err.flush();
            return 1;
        },
    }
}

test "no arguments prints usage and exits 2" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 2), try run(std.testing.allocator, io, &.{"rezig"}));
}

test "help exits 0" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 0), try run(std.testing.allocator, io, &.{ "rezig", "help" }));
}
