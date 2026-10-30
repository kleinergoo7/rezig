//! Raw ISO file access.

const std = @import("std");
const Io = std.Io;

pub const Error = error{ Truncated, AccessDenied, FileNotFound };

pub const Iso = struct {
    file: Io.File,
    size: u64,

    pub fn open(io: Io, path: []const u8) !Iso {
        const file = try Io.Dir.cwd().openFile(io, path, .{});
        errdefer file.close(io);
        const st = try file.stat(io);
        return .{ .file = file, .size = st.size };
    }

    pub fn readAt(self: *const Iso, io: Io, offset: u64, buf: []u8) Error!void {
        if (offset > self.size or buf.len > self.size - offset) return error.Truncated;
        const n = self.file.readPositionalAll(io, buf, offset) catch return error.AccessDenied;
        if (n != buf.len) return error.Truncated;
    }

    pub fn close(self: *Iso, io: Io) void {
        self.file.close(io);
    }
};

test "iso reads at an offset and rejects reads past the end" {
    const io = Io.Threaded.global_single_threaded.io();
    var iso = try Iso.open(io, "build.zig");
    defer iso.close(io);

    try std.testing.expect(iso.size > 16);

    var head: [5]u8 = undefined;
    try iso.readAt(io, 0, &head);
    try std.testing.expectEqualStrings("const", &head);

    var past: [1]u8 = undefined;
    try std.testing.expectError(error.Truncated, iso.readAt(io, iso.size, &past));
}
