//! Public CLI surface for rezig.

const std = @import("std");
const Io = std.Io;
const parse = @import("parse.zig");
const analyze = @import("analyze.zig");
const extract = @import("extract.zig");
const manifest = @import("manifest.zig");

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
    \\extract options:
    \\  --iso <path>   disc image
    \\  --out <dir>    output game tree
    \\  --key <path>   16-byte XEX key, optional; with it the XEX image is verified
    \\
;

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const [:0]const u8) !u8 {
    var err_buf: [1024]u8 = undefined;
    var err_writer = Io.File.stderr().writer(io, &err_buf);
    const err = &err_writer.interface;

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
        .extract => |opts| {
            const summary = extract.run(gpa, io, opts) catch |e| {
                try err.print("rezig extract: {s}: iso '{s}', out '{s}'\n", .{ @errorName(e), opts.iso, opts.out });
                try err.flush();
                return 1;
            };
            try printExtractSummary(io, opts, summary);
            return 0;
        },
        .analyze => |opts| {
            analyze.run(gpa, io, opts) catch |e| {
                try err.print("rezig analyze: {s}: tree '{s}', key '{s}'\n", .{ @errorName(e), opts.tree, opts.key });
                try err.flush();
                return 1;
            };
            return 0;
        },
        .codegen, .build, .run => {
            try err.writeAll("rezig: command not implemented yet\n");
            try err.flush();
            return 1;
        },
    }
}

fn printExtractSummary(io: Io, opts: parse.Extract, summary: extract.Summary) !void {
    var buf: [1024]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    try out.print("extracted {d} files, {d} bytes, skipped {d}\n", .{
        summary.files,
        summary.bytes,
        summary.skipped,
    });
    try out.print("xex: version {d}.{d}.{d}.{d}, image {s}\n", .{
        summary.xex_version[0],
        summary.xex_version[1],
        summary.xex_version[2],
        summary.xex_version[3],
        if (summary.image_verified) "verified" else "not verified",
    });

    if (summary.image_verified) {
        try out.print("next: rezig analyze --tree {s} --key <key>\n", .{opts.out});
    } else {
        try out.print("next: rezig extract --iso {s} --out {s} --key <key>\n", .{ opts.iso, opts.out });
    }
    try out.flush();
}

test "no arguments prints usage and exits 2" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 2), try run(std.testing.allocator, io, &.{"rezig"}));
}

test "help exits 0" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 0), try run(std.testing.allocator, io, &.{ "rezig", "help" }));
}

test "manifest tool version matches the package version" {
    try std.testing.expectEqualStrings("0.0.0", manifest.tool_version);
}
