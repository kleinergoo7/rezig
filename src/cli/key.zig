//! Key resolution: flag, environment, then the user's config file.
//! rezig never ships or embeds a key.

const std = @import("std");
const Io = std.Io;
const aes = @import("../xex/aes.zig");

pub const config_sub_path = ".config/rezig/xex.key";

pub const Paths = struct {
    env: ?[]const u8 = null,
    config: ?[]const u8 = null,
};

pub const Error = aes.LoadKeyError;

/// Returns the key, or null when no source is configured.
/// An explicitly configured source that is missing is an error, not a silent fallback.
pub fn resolve(io: Io, explicit: ?[]const u8, paths: Paths) Error!?[16]u8 {
    if (explicit) |path| return try loadOne(io, path);

    if (paths.env) |path| return try loadOne(io, path);

    if (paths.config) |path| {
        return loadOne(io, path) catch |e| switch (e) {
            error.FileNotFound => null,
            else => |other| return other,
        };
    }

    return null;
}

fn loadOne(io: Io, path: []const u8) Error![16]u8 {
    var key: [16]u8 = undefined;
    try aes.loadKey(io, path, &key);
    return key;
}

const testing = std.testing;

fn testIo() Io {
    return Io.Threaded.global_single_threaded.io();
}

fn writeKey(io: Io, tmp: *testing.TmpDir, name: []const u8, size: usize, path_buf: []u8) ![]const u8 {
    const bytes = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(bytes);
    for (bytes, 0..) |*b, i| b.* = @truncate(i + 1);
    try tmp.dir.writeFile(io, .{ .sub_path = name, .data = bytes });
    return std.fmt.bufPrint(path_buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

test "flag wins over environment and config" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var flag_buf: [256]u8 = undefined;
    var env_buf: [256]u8 = undefined;
    var config_buf: [256]u8 = undefined;
    const flag = try writeKey(io, &tmp, "flag.key", 16, &flag_buf);
    const env = try writeKey(io, &tmp, "env.key", 16, &env_buf);
    const config = try writeKey(io, &tmp, "config.key", 16, &config_buf);

    const key = try resolve(io, flag, .{ .env = env, .config = config });
    try testing.expectEqual(@as(u8, 1), key.?[0]);
}

test "environment is used when no flag is given" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var env_buf: [256]u8 = undefined;
    var config_buf: [256]u8 = undefined;
    const env = try writeKey(io, &tmp, "env.key", 16, &env_buf);
    _ = try writeKey(io, &tmp, "config.key", 16, &config_buf);

    const key = try resolve(io, null, .{ .env = env });
    try testing.expectEqual(@as(u8, 1), key.?[0]);
}

test "config is used when nothing else is set" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var config_buf: [256]u8 = undefined;
    const config = try writeKey(io, &tmp, "config.key", 16, &config_buf);

    const key = try resolve(io, null, .{ .config = config });
    try testing.expectEqual(@as(u8, 1), key.?[0]);
}

test "missing config file means no key" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var config_buf: [256]u8 = undefined;
    const config = try std.fmt.bufPrint(&config_buf, ".zig-cache/tmp/{s}/absent.key", .{tmp.sub_path});

    try testing.expectEqual(@as(?[16]u8, null), try resolve(io, null, .{ .config = config }));
}

test "missing explicit key file is an error" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/absent.key", .{tmp.sub_path});

    try testing.expectError(error.FileNotFound, resolve(io, path, .{}));
}

test "bad key size is not silently ignored" {
    const io = testIo();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: [256]u8 = undefined;
    const path = try writeKey(io, &tmp, "wide.key", 32, &buf);

    try testing.expectError(error.BadKeySize, resolve(io, path, .{}));
}
