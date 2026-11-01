//! TEMPORARY pre-import hang tracer. Delete after the hang is fixed.
//! Run: zig build trace-tmp
//! Loads Better16, runs the entry path in the interpreter with a small
//! budget, and dumps the last traced pcs plus the fault.

const std = @import("std");
const Io = std.Io;
const ppc = @import("rezig_ppc");
const runtime = @import("rezig_runtime");
const interp = @import("rezig_interp");
const xex = @import("rezig_xex");

test "trace better16 entry path" {
    const io = Io.Threaded.global_single_threaded.io();
    var key: [16]u8 = undefined;
    try xex.aes.loadKey(io, "data/keys/xex-debug.key", &key);
    var img = try xex.image.load(std.testing.allocator, io, "/home/reng/Downloads/xbox360test/Better16/default.xex", key);
    defer img.deinit(std.testing.allocator);

    const sections = try std.testing.allocator.alloc(ppc.analyze.CodeSection, img.sections.len);
    defer std.testing.allocator.free(sections);
    var count: usize = 0;
    for (img.sections) |s| {
        if (!img.isExecutable(s)) continue;
        sections[count] = .{ .addr = img.base_address + s.virtual_address, .bytes = img.sectionBytes(s) };
        count += 1;
    }
    var seeds: []u32 = &.{};
    for (img.sections) |s| {
        const n = std.mem.indexOfScalar(u8, &s.name, 0) orelse s.name.len;
        if (std.mem.eql(u8, s.name[0..n], ".pdata")) {
            seeds = try ppc.pdata.starts(std.testing.allocator, img.sectionBytes(s));
        }
    }
    defer if (seeds.len != 0) std.testing.allocator.free(seeds);

    const found = try ppc.analyze.functionsFrom(std.testing.allocator, sections[0..count], img.entry_point, seeds);
    defer ppc.analyze.freeFunctions(std.testing.allocator, found);

    const table = try std.testing.allocator.alloc(interp.Entry, found.len);
    defer std.testing.allocator.free(table);
    for (found, 0..) |f, i| table[i] = .{ .addr = f.addr, .words = f.words };

    var ctx = runtime.ctx.Ctx.init(.{ .base = img.base_address, .data = img.bytes });
    ctx.gpr[1] = img.base_address + @as(u32, @intCast(img.bytes.len)) - 0x100;
    ctx.budget = 20000;
    interp.dbg_on = true;
    const entry_words = for (table) |e| {
        if (e.addr == img.entry_point) break e.words;
    } else return error.EntryMissing;
    interp.runTable(&ctx, img.entry_point, entry_words, table) catch |e| {
        std.debug.print("TEMP runTable failed: {s}\n", .{@errorName(e)});
    };
    interp.dbg_on = false;
    std.debug.print("TEMP total={d} budget={d} depth={d} fault={s}@0x{X}\n", .{
        interp.dbg_total, ctx.budget, ctx.depth, @tagName(ctx.fault.kind), ctx.fault.addr,
    });
    std.debug.print("TEMP last pcs:\n", .{});
    var k: usize = 0;
    while (k < 16) : (k += 1) {
        const idx = (interp.dbg_pos + interp.dbg_ring.len - 16 + k) % interp.dbg_ring.len;
        std.debug.print("TEMP pc[{d}] = 0x{X}\n", .{ k, interp.dbg_ring[idx] });
    }
    std.debug.print("TEMP last calls:\n", .{});
    var c: usize = 0;
    while (c < 32) : (c += 1) {
        const idx = (interp.dbg_call_pos + interp.dbg_calls.len - 32 + c) % interp.dbg_calls.len;
        std.debug.print("TEMP call[{d}] = 0x{X}\n", .{ c, interp.dbg_calls[idx] });
    }
}
