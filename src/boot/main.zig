//! Minimal boot harness for the generated whole-image project.

const std = @import("std");
const Io = std.Io;
const image = @import("rezig_image").image;
const Ctx = @import("rezig_runtime").ctx.Ctx;
const slice = @import("slice");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    if (args.len < 2) {
        std.debug.print("usage: boot <xex>\n", .{});
        return;
    }

    var img = try image.load(gpa, init.io, args[1], null);
    defer img.deinit(gpa);

    var ctx = Ctx.init(.{ .base = img.base_address, .data = img.bytes });
    ctx.gpr[1] = img.base_address + @as(u32, @intCast(img.bytes.len)) - 0x100;
    ctx.budget = 1_000_000;

    std.debug.print("boot: base 0x{X} entry 0x{X} size 0x{X}\n", .{
        img.base_address, img.entry_point, img.bytes.len,
    });

    const handled = slice.dispatch(img.entry_point, &ctx);
    std.debug.print("boot: dispatch returned {} fault {s} at 0x{X} lr=0x{X} r3=0x{X} r4=0x{X} r5=0x{X}\n", .{
        handled, @tagName(ctx.fault.kind), ctx.fault.addr, ctx.lr, ctx.gpr[3], ctx.gpr[4], ctx.gpr[5],
    });
}
