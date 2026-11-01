//! Differential gate: emitted Zig versus the interpreter, on real selected functions.

const std = @import("std");
const slice = @import("slice");
const runtime = @import("rezig_runtime");
const interp = @import("rezig_interp");

const Ctx = runtime.ctx.Ctx;

const page_size: usize = 64 * 1024;
const page_base: u32 = 0x10000000;

fn splitmix(state: *u64) u64 {
    state.* +%= 0x9E3779B97F4A7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

test "emitted functions match the interpreter" {
    const table = try std.testing.allocator.alloc(interp.Entry, slice.functions.len);
    defer std.testing.allocator.free(table);
    for (slice.functions, 0..) |f, i| table[i] = .{ .addr = f.addr, .words = f.words };

    var cases: u32 = 0;

    for (slice.functions) |f| {
        var case: u32 = 0;
        while (case < 64) : (case += 1) {
            const seed = @as(u64, f.addr) * 64 + case;

            var page_a: [page_size]u8 = undefined;
            var page_b: [page_size]u8 = undefined;
            var fill = seed;
            for (0..page_size) |i| {
                const b: u8 = @truncate(splitmix(&fill));
                page_a[i] = b;
                page_b[i] = b;
            }

            var ctx_a = Ctx.init(.{ .base = page_base, .data = &page_a });
            var ctx_b = Ctx.init(.{ .base = page_base, .data = &page_b });
            ctx_a.budget = 16_384;
            ctx_b.budget = 16_384;

            var regs = seed ^ 0xA5A5_5A5A;
            for (&ctx_a.gpr) |*g| g.* = splitmix(&regs);
            for (ctx_a.gpr[3..11], 0..) |_, i| {
                const r = splitmix(&regs);
                ctx_a.gpr[3 + i] = if (case % 8 == 7)
                    page_base +% @as(u32, @truncate(r)) | 0xF000_0000
                else
                    page_base | (@as(u32, @truncate(r)) & 0xFFFC);
            }
            ctx_b.gpr = ctx_a.gpr;
            ctx_a.lr = @truncate(seed);
            ctx_b.lr = ctx_a.lr;

            interp.runTable(&ctx_a, f.addr, f.words, table) catch |e| {
                std.debug.print("addr 0x{X} case {d}: interpreter failed: {s}\n", .{ f.addr, case, @errorName(e) });
                return e;
            };
            if (!slice.dispatch(f.addr, &ctx_b)) {
                std.debug.print("addr 0x{X}: dispatch returned false\n", .{f.addr});
                return error.NotDispatched;
            }

            if (!std.mem.eql(u64, &ctx_a.gpr, &ctx_b.gpr)) {
                for (ctx_a.gpr, ctx_b.gpr, 0..) |expected, actual, i| {
                    if (expected != actual) {
                        std.debug.print("g_{X} case {d}: gpr[{d}] expected 0x{X} actual 0x{X}\n", .{ f.addr, case, i, expected, actual });
                    }
                }
                std.debug.print("  ctr {X}/{X} cr {X}/{X} lr {X}/{X} fault {s}@{X}/{X} vs {s}@{X}/{X}\n", .{
                    ctx_a.ctr,                  ctx_b.ctr,        ctx_a.cr,         ctx_b.cr,                   ctx_a.lr,         ctx_b.lr,
                    @tagName(ctx_a.fault.kind), ctx_a.fault.addr, ctx_a.fault.size, @tagName(ctx_b.fault.kind), ctx_b.fault.addr, ctx_b.fault.size,
                });
                return error.RegisterMismatch;
            }
            for (ctx_a.fpr, ctx_b.fpr, 0..) |expected, actual, i| {
                if (@as(u64, @bitCast(expected)) != @as(u64, @bitCast(actual))) {
                    std.debug.print("g_{X} case {d}: fpr[{d}] expected 0x{X} actual 0x{X}\n", .{
                        f.addr, case, i, @as(u64, @bitCast(expected)), @as(u64, @bitCast(actual)),
                    });
                    return error.RegisterMismatch;
                }
            }
            if (!std.mem.eql(u8, std.mem.asBytes(&ctx_a.vmx), std.mem.asBytes(&ctx_b.vmx))) {
                for (ctx_a.vmx, ctx_b.vmx, 0..) |expected, actual, i| {
                    if (std.mem.eql(u8, &expected, &actual)) continue;
                    std.debug.print("g_{X} case {d}: vmx[{d}] expected {x} actual {x}\n", .{ f.addr, case, i, expected, actual });
                    return error.RegisterMismatch;
                }
            }
            if (ctx_a.cr != ctx_b.cr) {
                std.debug.print("g_{X} case {d}: cr expected 0x{X} actual 0x{X}\n", .{ f.addr, case, ctx_a.cr, ctx_b.cr });
                return error.RegisterMismatch;
            }
            if (ctx_a.lr != ctx_b.lr or ctx_a.ctr != ctx_b.ctr or ctx_a.xer != ctx_b.xer) {
                std.debug.print("g_{X} case {d}: lr/ctr/xer differ\n", .{ f.addr, case });
                return error.RegisterMismatch;
            }
            if (ctx_a.fault.kind != ctx_b.fault.kind or ctx_a.fault.addr != ctx_b.fault.addr or ctx_a.fault.size != ctx_b.fault.size) {
                std.debug.print("g_{X} case {d}: fault expected {s}@0x{X}/{d} actual {s}@0x{X}/{d}\n", .{
                    f.addr,                     case,
                    @tagName(ctx_a.fault.kind), ctx_a.fault.addr,
                    ctx_a.fault.size,           @tagName(ctx_b.fault.kind),
                    ctx_b.fault.addr,           ctx_b.fault.size,
                });
                return error.FaultMismatch;
            }
            for (page_a, page_b, 0..) |expected, actual, i| {
                if (expected != actual) {
                    std.debug.print("g_{X} case {d}: memory[{d}] expected 0x{X} actual 0x{X}\n", .{ f.addr, case, i, expected, actual });
                    return error.MemoryMismatch;
                }
            }

            cases += 1;
        }
    }

    std.debug.print("{d} functions x 64 cases: PASS ({d} cases)\n", .{ slice.functions.len, cases });
}
