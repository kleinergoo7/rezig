//! Minimal boot harness for the generated whole-image project.

const std = @import("std");
const Io = std.Io;
const image = @import("rezig_image").image;
const aes = @import("rezig_image").aes;
const Ctx = @import("rezig_runtime").ctx.Ctx;
const slice = @import("slice");

/// Guest instructions per boot run before the harness stops and reports.
/// Large enough for init chains, small enough to bound a spin loop.
const boot_budget: u32 = 1_000_000;
/// Bytes reserved below the image end for the initial guest stack.
const stack_reserve: u32 = 0x100;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    if (args.len < 2) {
        std.debug.print("usage: boot <xex> [key]\n", .{});
        return;
    }

    var key: ?[16]u8 = null;
    if (args.len >= 3) {
        var loaded: [16]u8 = undefined;
        try aes.loadKey(init.io, args[2], &loaded);
        key = loaded;
    }

    var img = try image.load(gpa, init.io, args[1], key);
    defer img.deinit(gpa);

    var ctx = Ctx.init(.{ .base = img.base_address, .data = img.bytes });
    // Stack top 256 bytes below the image end, matching the XEX loader.
    ctx.gpr[1] = img.base_address + @as(u32, @intCast(img.bytes.len)) - stack_reserve;
    ctx.budget = boot_budget;
    ctx.budget = boot_budget;

    std.debug.print("boot: base 0x{X} entry 0x{X} size 0x{X}\n", .{
        img.base_address, img.entry_point, img.bytes.len,
    });

    const handled = slice.dispatch(img.entry_point, &ctx);
    std.debug.print("boot: dispatch returned {} fault {s} at 0x{X} lr=0x{X} r3=0x{X} r4=0x{X} r5=0x{X} budget={d} depth={d}\n", .{
        handled, @tagName(ctx.fault.kind), ctx.fault.addr, ctx.lr, ctx.gpr[3], ctx.gpr[4], ctx.gpr[5], ctx.budget, ctx.depth,
    });
}
