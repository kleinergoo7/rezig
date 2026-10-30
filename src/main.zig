//! Rezig CLI entry point.

const std = @import("std");
const cli = @import("cli/root.zig");

pub fn main(init: std.process.Init) !u8 {
    var safe = std.heap.SafeAllocator.init(init.gpa, .{});
    defer _ = safe.deinit();
    const gpa = safe.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    const env_key_path = init.environ_map.get("REZIG_XEX_KEY");
    const home = init.environ_map.get("HOME") orelse init.environ_map.get("USERPROFILE");

    return try cli.run(gpa, init.io, args, env_key_path, home);
}
