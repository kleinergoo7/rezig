//! Public CLI surface for rezig.

const std = @import("std");
const Io = std.Io;
const parse = @import("parse.zig");
const analyze = @import("analyze.zig");
const codegen = @import("codegen.zig");
const xex_convert = @import("xex.zig");
const coverage = @import("coverage.zig");
const extract = @import("extract.zig");
const keys = @import("key.zig");
const manifest = @import("manifest.zig");

pub const usage =
    \\usage: rezig <command> [options]
    \\
    \\commands:
    \\  extract   Copy the disc tree from an ISO and verify it
    \\  analyze   Parse the XEX and report version, entry point and sections
    \\  coverage  Report decoder and emitter coverage over discovered code
    \\  xex       Rewrite an XEX as an unencrypted, uncompressed copy
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

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const [:0]const u8,
    env_key_path: ?[]const u8,
    home: ?[]const u8,
) !u8 {
    var config_buf: [512]u8 = undefined;
    const config_path: ?[]const u8 = if (home) |h|
        try std.fmt.bufPrint(&config_buf, "{s}/{s}", .{ h, keys.config_sub_path })
    else
        null;
    const key_paths = keys.Paths{ .env = env_key_path, .config = config_path };

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
            const key = keys.resolve(io, opts.key, key_paths) catch |e| {
                try printKeyError(io, err, e, opts.key, key_paths);
                return 1;
            };
            const summary = extract.run(gpa, io, opts, key) catch |e| {
                try err.print("rezig extract: {s}: iso '{s}', out '{s}'", .{ @errorName(e), opts.iso, opts.out });
                try err.writeAll("\n");
                try err.flush();
                return 1;
            };
            try printExtractSummary(io, opts, summary);
            return 0;
        },
        .analyze => |opts| {
            const key = keys.resolve(io, opts.key, key_paths) catch |e| {
                try printKeyError(io, err, e, opts.key, key_paths);
                return 1;
            };
            analyze.run(gpa, io, opts, key) catch |e| {
                if (e == error.KeyMissing) {
                    try printKeyMissing(io, err, key_paths);
                } else {
                    try err.print("rezig analyze: {s}\n", .{@errorName(e)});
                }
                try err.flush();
                return 1;
            };
            return 0;
        },
        .coverage => |opts| {
            const key = keys.resolve(io, opts.key, key_paths) catch |e| {
                try printKeyError(io, err, e, opts.key, key_paths);
                return 1;
            };
            coverage.run(gpa, io, opts, key) catch |e| {
                try err.print("rezig coverage: {s}\n", .{@errorName(e)});
                try err.flush();
                return 1;
            };
            return 0;
        },
        .xex_convert => |opts| {
            const key = keys.resolve(io, opts.key, key_paths) catch |e| {
                try printKeyError(io, err, e, opts.key, key_paths);
                return 1;
            };
            xex_convert.run(gpa, io, opts, key) catch |e| {
                if (e == error.KeyMissing) {
                    try printKeyMissing(io, err, key_paths);
                } else {
                    try err.print("rezig xex: {s}\n", .{@errorName(e)});
                }
                try err.flush();
                return 1;
            };
            return 0;
        },
        .codegen => |opts| {
            const key = keys.resolve(io, opts.key, key_paths) catch |e| {
                try printKeyError(io, err, e, opts.key, key_paths);
                return 1;
            };
            codegen.run(gpa, io, opts, key) catch |e| {
                if (e == error.KeyMissing) {
                    try printKeyMissing(io, err, key_paths);
                } else {
                    try err.print("rezig codegen: {s}\n", .{@errorName(e)});
                }
                try err.flush();
                return 1;
            };
            return 0;
        },
        .build, .run => {
            try err.writeAll("rezig: command not implemented yet\n");
            try err.flush();
            return 1;
        },
    }
}

fn printKeyError(
    io: Io,
    writer: anytype,
    e: anyerror,
    explicit: ?[]const u8,
    paths: keys.Paths,
) !void {
    try writer.print("rezig: {s}", .{@errorName(e)});
    const used = explicit orelse paths.env orelse paths.config orelse "";
    if (used.len != 0) {
        const st = Io.Dir.cwd().statFile(io, used, .{}) catch null;
        try writer.print(": key file '{s}'", .{used});
        if (st) |s| try writer.print(" is {d} bytes, expected 16", .{s.size});
    }
    try writer.writeAll("\n");
    try writer.flush();
}

fn printKeyMissing(io: Io, writer: anytype, paths: keys.Paths) !void {
    _ = io;
    try writer.writeAll("rezig: KeyMissing: this XEX is encrypted. Provide a 16-byte key one of these ways:\n");
    if (paths.config) |config| {
        try writer.print("  - place it at {s} (raw bytes, chmod 600)\n", .{config});
    }
    try writer.writeAll("  - set REZIG_XEX_KEY to a key file path\n");
    try writer.writeAll("  - pass --key <path>\n");
    try writer.writeAll("  - or pass --xex <unlocked.xex> for an already-decrypted image\n");
    try writer.flush();
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
    try std.testing.expectEqual(@as(u8, 2), try run(std.testing.allocator, io, &.{"rezig"}, null, null));
}

test "help exits 0" {
    const io = Io.Threaded.global_single_threaded.io();
    try std.testing.expectEqual(@as(u8, 0), try run(std.testing.allocator, io, &.{ "rezig", "help" }, null, null));
}

test "manifest tool version matches the package version" {
    try std.testing.expectEqualStrings("0.0.0", manifest.tool_version);
}
