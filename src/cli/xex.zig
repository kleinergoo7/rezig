//! `rezig xex`: rewrite an XEX as an unencrypted, uncompressed copy.

const std = @import("std");
const Io = std.Io;
const xextool = @import("xextool");
const parse = @import("parse.zig");

pub const Options = parse.Xex;

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    const user_key = key orelse return error.KeyMissing;
    // The image key in the security info is always encrypted with the console
    // key, even in an unlocked file, so the user's key is used for both.
    const keys = xextool.xex.keys.Keys.uniform(user_key);

    const bytes = try Io.Dir.cwd().readFileAlloc(io, opts.in, allocator, .limited(1 << 40));
    defer allocator.free(bytes);

    var xex = xextool.xex.model.Xex.init(allocator);
    defer xex.deinit();

    _ = try xextool.xex.reader.readBytes(&xex, bytes, keys);

    xex.is_encrypted = false;
    xex.is_raw = true;
    xex.is_binary = false;
    xex.is_compressed = false;
    xex.is_delta_compressed = false;

    var out = xextool.DataBlock.init();
    defer out.deinit(allocator);
    try xextool.xex.writer.write(&xex, &out, keys);

    var atomic = try Io.Dir.cwd().createFileAtomic(io, opts.out, .{ .replace = true, .make_path = true });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, out.data());
    try atomic.replace(io);

    var buf: [1024]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const stdout = &writer.interface;
    try stdout.print("wrote {s}: {d} bytes, unencrypted, uncompressed\n", .{ opts.out, out.size() });
    try stdout.flush();
}
