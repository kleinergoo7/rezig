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
/// Bytes reserved below the initial stack pointer.
const stack_reserve: u32 = 0x100;
/// Loader scratch the import fixups write into (guest data cells).
const scratch_span: u32 = 0x10000;
/// Guest range host services allocate from (pools, virtual memory).
const arena_span: u32 = 256 << 20;
/// Guest stack above the arena; the stack grows down into this span.
const stack_span: u32 = 1 << 20;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    if (args.len < 2) {
        std.debug.print("usage: boot <xex> [key] [budget]\n", .{});
        return;
    }

    var key: ?[16]u8 = null;
    if (args.len >= 3 and !std.mem.eql(u8, args[2], "-")) {
        var loaded: [16]u8 = undefined;
        try aes.loadKey(init.io, args[2], &loaded);
        key = loaded;
    }

    var budget = boot_budget;
    if (args.len >= 4) {
        budget = try std.fmt.parseInt(u32, args[3], 10);
    }

    var img = try image.load(gpa, init.io, args[1], key);
    defer img.deinit(gpa);

    // Guest memory is the whole virtual image, not only the stored payload:
    // the PE optional header covers zero pages the XEX does not carry.
    const image_span: u32 = @max(img.size_of_image, @as(u32, @intCast(img.bytes.len)));
    const total_span = @as(u64, image_span) + scratch_span + arena_span + stack_span;
    if (total_span > std.math.maxInt(u32)) return error.ImageTooLarge;
    const mem = try gpa.alloc(u8, @intCast(total_span));
    defer gpa.free(mem);
    @memset(mem, 0);
    @memcpy(mem[0..img.bytes.len], img.bytes);

    var ctx = Ctx.init(.{ .base = img.base_address, .data = mem });
    ctx.gpr[1] = img.base_address + @as(u32, @intCast(total_span)) - stack_reserve;
    ctx.budget = budget;
    // Layout: image, loader scratch, arena, stack.
    ctx.arena_base = img.base_address + image_span + scratch_span;
    ctx.arena_end = ctx.arena_base + arena_span;
    // Never run on with a bad state: the first fault ends the run.
    ctx.strict_faults = true;

    // Resolve the IAT slots before the entry point runs. Data-export cells live
    // in the loader scratch just past the image.
    slice.init(&ctx, img.base_address + image_span);

    std.debug.print("boot: base 0x{X} entry 0x{X} size 0x{X} virtual 0x{X}\n", .{
        img.base_address, img.entry_point, img.bytes.len, img.size_of_image,
    });

    const handled = slice.dispatch(img.entry_point, &ctx);
    std.debug.print("boot: dispatch returned {} fault {s} at 0x{X} pc=0x{X} lr=0x{X} r3=0x{X} r4=0x{X} r5=0x{X} budget={d} halted={} depth={d}\n", .{
        handled, @tagName(ctx.fault.kind), ctx.fault.addr, ctx.fault.pc, ctx.lr, ctx.gpr[3], ctx.gpr[4], ctx.gpr[5], ctx.budget, ctx.halted, ctx.depth,
    });
}
