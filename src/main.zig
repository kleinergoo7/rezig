//! Rezig CLI entry point.

const std = @import("std");
const cli = @import("cli/root.zig");

pub fn main(init: std.process.Init) !void {
    var safe = std.heap.SafeAllocator.init(init.gpa, .{});
    defer _ = safe.deinit();
    const gpa = safe.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    const code = try cli.run(gpa, init.io, args);
    std.process.exit(code);
}
